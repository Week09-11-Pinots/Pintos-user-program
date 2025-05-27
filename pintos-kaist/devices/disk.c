#include "devices/disk.h"
#include <ctype.h>
#include <debug.h>
#include <stdbool.h>
#include <stdio.h>
#include "devices/timer.h"
#include "threads/io.h"
#include "threads/interrupt.h"
#include "threads/synch.h"

/* 이 파일의 코드는 ATA (IDE) 컨트롤러에 대한 인터페이스입니다. 
	[ATA-3] 표준을 준수하려고 시도합니다. */

/* ATA 명령 블록 포트 주소. */
#define reg_data(CHANNEL) ((CHANNEL)->reg_base + 0)	  /* 데이터. */
#define reg_error(CHANNEL) ((CHANNEL)->reg_base + 1)  /* Error. */
#define reg_nsect(CHANNEL) ((CHANNEL)->reg_base + 2)  /* Sector Count. */
#define reg_lbal(CHANNEL) ((CHANNEL)->reg_base + 3)	  /* LBA 0:7. */
#define reg_lbam(CHANNEL) ((CHANNEL)->reg_base + 4)	  /* LBA 15:8. */
#define reg_lbah(CHANNEL) ((CHANNEL)->reg_base + 5)	  /* LBA 23:16. */
#define reg_device(CHANNEL) ((CHANNEL)->reg_base + 6) /* Device/LBA 27:24. */
#define reg_status(CHANNEL) ((CHANNEL)->reg_base + 7) /* Status (r/o). */
#define reg_command(CHANNEL) reg_status(CHANNEL)	  /* Command (w/o). */

/* ATA 제어 블록 포트 주소.
	(비유산 ATA 컨트롤러를 지원한다면 이 방식은 충분히 유연하지 않을 수 있지만,
	우리가 하는 작업에는 적합합니다.) */
#define reg_ctl(CHANNEL) ((CHANNEL)->reg_base + 0x206) /* 제어 (쓰기 전용). */
#define reg_alt_status(CHANNEL) reg_ctl(CHANNEL)	   /* Alt Status (r/o). */

/* Alternate Status Register bits. */
#define STA_BSY 0x80  /* Busy. */
#define STA_DRDY 0x40 /* Device Ready. */
#define STA_DRQ 0x08  /* Data Request. */

/* Control Register bits. */
#define CTL_SRST 0x04 /* Software Reset. */

/* Device Register bits. */
#define DEV_MBS 0xa0 /* Must be set. */
#define DEV_LBA 0x40 /* Linear based addressing. */
#define DEV_DEV 0x10 /* Select device: 0=master, 1=slave. */

/* 명령어.
	우리가 사용하는 작은 하위 집합이지만 훨씬 더 많은 명령어가 정의되어 있습니다. */
#define CMD_IDENTIFY_DEVICE 0xec	/* 장치 식별 (IDENTIFY DEVICE). */
#define CMD_READ_SECTOR_RETRY 0x20	/* READ SECTOR with retries. */
#define CMD_WRITE_SECTOR_RETRY 0x30 /* WRITE SECTOR with retries. */

/* An ATA device. */
struct disk
{
	char name[8];			 /* Name, e.g. "hd0:1". */
	struct channel *channel; /* Channel disk is on. */
	int dev_no;				 /* Device 0 or 1 for master or slave. */

	bool is_ata;			/* 1=This device is an ATA disk. */
	disk_sector_t capacity; /* Capacity in sectors (if is_ata). */

	long long read_cnt;	 /* Number of sectors read. */
	long long write_cnt; /* Number of sectors written. */
};

/* ATA 채널(컨트롤러).
	각 채널은 최대 두 개의 디스크를 제어할 수 있습니다. */
struct channel
{
	char name[8];	   /* 이름(예: "hd0" 등). */
	uint16_t reg_base; /* 기본 I/O 포트. */
	uint8_t irq;	   /* 사용 중인 인터럽트 번호. */

	struct lock lock;				  /* 컨트롤러에 접근하려면 반드시 획득해야 하는 락. */
	bool expecting_interrupt;		  /* 인터럽트가 예상되는 경우 true,  
										그렇지 않으면(예상치 못한 인터럽트면) false. */
	struct semaphore completion_wait; /* 인터럽트 핸들러에 의해 up되는 세마포어. */

	struct disk devices[2]; /* 이 채널에 연결된 디바이스들. */
};

/* We support the two "legacy" ATA channels found in a standard PC. */
#define CHANNEL_CNT 2
static struct channel channels[CHANNEL_CNT];

static void reset_channel(struct channel *);
static bool check_device_type(struct disk *);
static void identify_ata_device(struct disk *);

static void select_sector(struct disk *, disk_sector_t);
static void issue_pio_command(struct channel *, uint8_t command);
static void input_sector(struct channel *, void *);
static void output_sector(struct channel *, const void *);

static void wait_until_idle(const struct disk *);
static bool wait_while_busy(const struct disk *);
static void select_device(const struct disk *);
static void select_device_wait(const struct disk *);

static void interrupt_handler(struct intr_frame *);

/* Initialize the disk subsystem and detect disks. */
void disk_init(void)
{
	size_t chan_no;

	for (chan_no = 0; chan_no < CHANNEL_CNT; chan_no++)
	{
		struct channel *c = &channels[chan_no];
		int dev_no;

		/* Initialize channel. */
		snprintf(c->name, sizeof c->name, "hd%zu", chan_no);
		switch (chan_no)
		{
		case 0:
			c->reg_base = 0x1f0;
			c->irq = 14 + 0x20;
			break;
		case 1:
			c->reg_base = 0x170;
			c->irq = 15 + 0x20;
			break;
		default:
			NOT_REACHED();
		}
		lock_init(&c->lock);
		c->expecting_interrupt = false;
		sema_init(&c->completion_wait, 0);

		/* Initialize devices. */
		for (dev_no = 0; dev_no < 2; dev_no++)
		{
			struct disk *d = &c->devices[dev_no];
			snprintf(d->name, sizeof d->name, "%s:%d", c->name, dev_no);
			d->channel = c;
			d->dev_no = dev_no;

			d->is_ata = false;
			d->capacity = 0;

			d->read_cnt = d->write_cnt = 0;
		}

		/* Register interrupt handler. */
		intr_register_ext(c->irq, interrupt_handler, c->name);

		/* Reset hardware. */
		reset_channel(c);

		/* Distinguish ATA hard disks from other devices. */
		if (check_device_type(&c->devices[0]))
			check_device_type(&c->devices[1]);

		/* Read hard disk identity information. */
		for (dev_no = 0; dev_no < 2; dev_no++)
			if (c->devices[dev_no].is_ata)
				identify_ata_device(&c->devices[dev_no]);
	}

	/* DO NOT MODIFY BELOW LINES. */
	register_disk_inspect_intr();
}

/* Prints disk statistics. */
void disk_print_stats(void)
{
	int chan_no;

	for (chan_no = 0; chan_no < CHANNEL_CNT; chan_no++)
	{
		int dev_no;

		for (dev_no = 0; dev_no < 2; dev_no++)
		{
			struct disk *d = disk_get(chan_no, dev_no);
			if (d != NULL && d->is_ata)
				printf("%s: %lld reads, %lld writes\n",
					   d->name, d->read_cnt, d->write_cnt);
		}
	}
}

/* CHAN_NO로 번호가 매겨진 채널 내에서 DEV_NO(0 또는 1, 각각 마스터 또는 슬레이브)로
번호가 매겨진 디스크를 반환합니다.

	Pintos는 디스크를 다음과 같이 사용합니다:
0:0 - 부트로더, 커맨드 라인 인자, 운영체제 커널
0:1 - 파일 시스템
1:0 - 스크래치
1:1 - 스왑
*/
struct disk *
disk_get(int chan_no, int dev_no)
{
	ASSERT(dev_no == 0 || dev_no == 1);

	if (chan_no < (int)CHANNEL_CNT)
	{
		struct disk *d = &channels[chan_no].devices[dev_no];
		if (d->is_ata)
			return d;
	}
	return NULL;
}

/* 디스크 D의 크기를 DISK_SECTOR_SIZE 바이트 섹터 단위로 반환합니다. */
disk_sector_t
disk_size(struct disk *d)
{
	ASSERT(d != NULL);

	return d->capacity;
}

/* 디스크 D에서 섹터 SEC_NO를 읽어 BUFFER에 저장합니다.
   BUFFER는 DISK_SECTOR_SIZE 바이트만큼의 공간이 있어야 합니다.
   내부적으로 디스크 접근을 동기화하므로, 별도의 디스크별 락은 필요하지 않습니다. */
   void disk_read(struct disk *d, disk_sector_t sec_no, void *buffer)
{
	struct channel *c;

	ASSERT(d != NULL);
	ASSERT(buffer != NULL);

	c = d->channel;
	lock_acquire(&c->lock);
	select_sector(d, sec_no);
	issue_pio_command(c, CMD_READ_SECTOR_RETRY);
	sema_down(&c->completion_wait);
	if (!wait_while_busy(d))
		PANIC("%s: disk read failed, sector=%" PRDSNu, d->name, sec_no);
	input_sector(c, buffer);
	d->read_cnt++;
	lock_release(&c->lock);
}

/* BUFFER에 있는 데이터를 디스크 D의 섹터 SEC_NO에 기록합니다.
   BUFFER는 DISK_SECTOR_SIZE 바이트를 포함해야 합니다.
   디스크가 데이터를 받았음을 확인한 후 반환합니다.
   내부적으로 디스크 접근을 동기화하므로, 별도의 디스크별 락은 필요하지 않습니다. */
   void disk_write(struct disk *d, disk_sector_t sec_no, const void *buffer)
{
	struct channel *c;

	ASSERT(d != NULL);
	ASSERT(buffer != NULL);

	c = d->channel;
	lock_acquire(&c->lock);
	select_sector(d, sec_no);
	issue_pio_command(c, CMD_WRITE_SECTOR_RETRY);
	if (!wait_while_busy(d))
		PANIC("%s: disk write failed, sector=%" PRDSNu, d->name, sec_no);
	output_sector(c, buffer);
	sema_down(&c->completion_wait);
	d->write_cnt++;
	lock_release(&c->lock);
}

/* 디스크 감지 및 식별. */

static void print_ata_string(char *string, size_t size);

/* ATA 채널을 리셋하고, 해당 채널에 연결된 모든 디바이스가 리셋을 완료할 때까지 대기합니다. */
static void
reset_channel(struct channel *c)
{
	bool present[2];
	int dev_no;

	/* ATA 리셋 순서는 어떤 디바이스가 존재하는지에 따라 달라지므로,
	먼저 디바이스의 존재 여부를 확인합니다. */
	for (dev_no = 0; dev_no < 2; dev_no++)
	{
		struct disk *d = &c->devices[dev_no];

		select_device(d);

		outb(reg_nsect(c), 0x55);
		outb(reg_lbal(c), 0xaa);

		outb(reg_nsect(c), 0xaa);
		outb(reg_lbal(c), 0x55);

		outb(reg_nsect(c), 0x55);
		outb(reg_lbal(c), 0xaa);

		present[dev_no] = (inb(reg_nsect(c)) == 0x55 && inb(reg_lbal(c)) == 0xaa);
	}

	/* 소프트 리셋 시퀀스를 실행하면, 부수적으로 디바이스 0이 선택됩니다.
	또한 인터럽트를 활성화합니다. */
	outb(reg_ctl(c), 0);
	timer_usleep(10);
	outb(reg_ctl(c), CTL_SRST);
	timer_usleep(10);
	outb(reg_ctl(c), 0);

	timer_msleep(150);

	/* 디바이스 0의 BSY(바쁨) 비트가 해제될 때까지 대기합니다. */
	if (present[0])
	{
		select_device(&c->devices[0]);
		wait_while_busy(&c->devices[0]);
	}

	/* 디바이스 1의 BSY(바쁨) 비트가 해제될 때까지 대기합니다. */
	if (present[1])
	{
		int i;

		select_device(&c->devices[1]);
		for (i = 0; i < 3000; i++)
		{
			if (inb(reg_nsect(c)) == 1 && inb(reg_lbal(c)) == 1)
				break;
			timer_msleep(10);
		}
		wait_while_busy(&c->devices[1]);
	}
}

/* 디바이스 D가 ATA 디스크인지 확인하고, D의 is_ata 멤버를 적절히 설정합니다.
   D가 디바이스 0(마스터)이면, 이 채널에 슬레이브(디바이스 1)가 존재할 가능성이 있으면 true를 반환합니다.
   D가 디바이스 1(슬레이브)인 경우 반환값은 의미가 없습니다. */

static bool
check_device_type(struct disk *d)
{
	struct channel *c = d->channel;
	uint8_t error, lbam, lbah, status;

	select_device(d);

	error = inb(reg_error(c));
	lbam = inb(reg_lbam(c));
	lbah = inb(reg_lbah(c));
	status = inb(reg_status(c));

	if ((error != 1 && (error != 0x81 || d->dev_no == 1)) || (status & STA_DRDY) == 0 || (status & STA_BSY) != 0)
	{
		d->is_ata = false;
		return error != 0x81;
	}
	else
	{
		d->is_ata = (lbam == 0 && lbah == 0) || (lbam == 0x3c && lbah == 0xc3);
		return true;
	}
}

/* 디스크 D에 IDENTIFY DEVICE 명령을 보내고, 응답을 읽어옵니다.
   결과를 바탕으로 D의 capacity 멤버를 초기화하고,
   디스크 정보를 콘솔에 출력합니다. */
static void
identify_ata_device(struct disk *d)
{
	struct channel *c = d->channel;
	uint16_t id[DISK_SECTOR_SIZE / 2];

	ASSERT(d->is_ata);

	/* IDENTIFY DEVICE 명령을 보내고, 디바이스의 응답이 준비되었음을 알리는 인터럽트를 기다린 후,
	데이터를 버퍼에 읽어옵니다. */

	select_device_wait(d);
	issue_pio_command(c, CMD_IDENTIFY_DEVICE);
	sema_down(&c->completion_wait);
	if (!wait_while_busy(d))
	{
		d->is_ata = false;
		return;
	}
	input_sector(c, id);

	/* Calculate capacity. */
	d->capacity = id[60] | ((uint32_t)id[61] << 16);

	/* Print identification message. */
	printf("%s: detected %'" PRDSNu " sector (", d->name, d->capacity);
	if (d->capacity > 1024 / DISK_SECTOR_SIZE * 1024 * 1024)
		printf("%" PRDSNu " GB",
			   d->capacity / (1024 / DISK_SECTOR_SIZE * 1024 * 1024));
	else if (d->capacity > 1024 / DISK_SECTOR_SIZE * 1024)
		printf("%" PRDSNu " MB", d->capacity / (1024 / DISK_SECTOR_SIZE * 1024));
	else if (d->capacity > 1024 / DISK_SECTOR_SIZE)
		printf("%" PRDSNu " kB", d->capacity / (1024 / DISK_SECTOR_SIZE));
	else
		printf("%" PRDSNu " byte", d->capacity * DISK_SECTOR_SIZE);
	printf(") disk, model \"");
	print_ata_string((char *)&id[27], 40);
	printf("\", serial \"");
	print_ata_string((char *)&id[10], 20);
	printf("\"\n");
}

/* STRING을 출력합니다. 이 문자열은 SIZE 바이트로 구성되어 있으며,
   각 2바이트 쌍이 뒤집힌 형태로 저장되어 있습니다.
   끝에 있는 공백이나 널 문자는 출력하지 않습니다. */
static void
print_ata_string(char *string, size_t size)
{
	size_t i;

	/* 마지막으로 공백이 아니고 널이 아닌 문자를 찾습니다. */
	for (; size > 0; size--)
	{
		int c = string[(size - 1) ^ 1];
		if (c != '\0' && !isspace(c))
			break;
	}

	/* Print. */
	for (i = 0; i < size; i++)
		printf("%c", string[i ^ 1]);
}

/* 디바이스 D를 선택하고, 준비될 때까지 기다린 다음,
   SEC_NO를 디스크의 섹터 선택 레지스터에 기록합니다. (LBA 모드를 사용함) */
static void
select_sector(struct disk *d, disk_sector_t sec_no)
{
	struct channel *c = d->channel;

	ASSERT(sec_no < d->capacity);
	ASSERT(sec_no < (1UL << 28));

	select_device_wait(d);
	outb(reg_nsect(c), 1);
	outb(reg_lbal(c), sec_no);
	outb(reg_lbam(c), sec_no >> 8);
	outb(reg_lbah(c), (sec_no >> 16));
	outb(reg_device(c),
		 DEV_MBS | DEV_LBA | (d->dev_no == 1 ? DEV_DEV : 0) | (sec_no >> 24));
}

/* 채널 C에 COMMAND를 기록하고, 완료 인터럽트를 받을 준비를 합니다. */
static void
issue_pio_command(struct channel *c, uint8_t command)
{
	/* 인터럽트가 활성화되어 있어야만, 완료 핸들러에서 세마포어를 up할 수 있습니다. */
	ASSERT(intr_get_level() == INTR_ON);

	c->expecting_interrupt = true;
	outb(reg_command(c), command);
}

/* 채널 C의 데이터 레지스터에서 PIO 모드로 섹터를 읽어 SECTOR에 저장합니다.
   SECTOR는 DISK_SECTOR_SIZE 바이트의 공간이 있어야 합니다. */
static void
input_sector(struct channel *c, void *sector)
{
	insw(reg_data(c), sector, DISK_SECTOR_SIZE / 2);
}

/* SECTOR의 데이터를 PIO 모드로 채널 C의 데이터 레지스터에 기록합니다.
   SECTOR는 DISK_SECTOR_SIZE 바이트를 포함해야 합니다. */
static void
output_sector(struct channel *c, const void *sector)
{
	outsw(reg_data(c), sector, DISK_SECTOR_SIZE / 2);
}

/* 저수준 ATA 기본 연산들. */

/* 컨트롤러가 유휴 상태가 될 때까지(즉, 상태 레지스터의 BSY와 DRQ 비트가 해제될 때까지) 최대 10초 동안 대기합니다.

   부수적으로, 상태 레지스터를 읽으면 대기 중인 인터럽트가 모두 클리어됩니다. */
static void
wait_until_idle(const struct disk *d)
{
	int i;

	for (i = 0; i < 1000; i++)
	{
		if ((inb(reg_status(d->channel)) & (STA_BSY | STA_DRQ)) == 0)
			return;
		timer_usleep(10);
	}

	printf("%s: idle timeout\n", d->name);
}

/* 디스크 D의 BSY 비트가 해제될 때까지 최대 30초 동안 대기한 후,
   DRQ 비트의 상태를 반환합니다.
   ATA 표준에 따르면, 디스크가 리셋을 완료하는 데 이 정도 시간이 걸릴 수 있습니다. */
static bool
wait_while_busy(const struct disk *d)
{
	struct channel *c = d->channel;
	int i;

	for (i = 0; i < 3000; i++)
	{
		if (i == 700)
			printf("%s: busy, waiting...", d->name);
		if (!(inb(reg_alt_status(c)) & STA_BSY))
		{
			if (i >= 700)
				printf("ok\n");
			return (inb(reg_alt_status(c)) & STA_DRQ) != 0;
		}
		timer_msleep(10);
	}

	printf("failed\n");
	return false;
}

/* D의 채널을 설정하여, 이제 D가 선택된 디스크가 되도록 합니다. */
static void
select_device(const struct disk *d)
{
	struct channel *c = d->channel;
	uint8_t dev = DEV_MBS;
	if (d->dev_no == 1)
		dev |= DEV_DEV;
	outb(reg_device(c), dev);
	inb(reg_alt_status(c));
	timer_nsleep(400);
}

/* select_device()처럼 D를 해당 채널에서 선택하지만,
   선택 전후로 채널이 유휴 상태가 될 때까지 대기합니다. */
static void
select_device_wait(const struct disk *d)
{
	wait_until_idle(d);
	select_device(d);
	wait_until_idle(d);
}

/* ATA interrupt handler. */
static void
interrupt_handler(struct intr_frame *f)
{
	struct channel *c;

	for (c = channels; c < channels + CHANNEL_CNT; c++)
		if (f->vec_no == c->irq)
		{
			if (c->expecting_interrupt)
			{
				inb(reg_status(c));			  /* Acknowledge interrupt. */
				sema_up(&c->completion_wait); /* Wake up waiter. */
			}
			else
				printf("%s: unexpected interrupt\n", c->name);
			return;
		}

	NOT_REACHED();
}

static void
inspect_read_cnt(struct intr_frame *f)
{
	struct disk *d = disk_get(f->R.rdx, f->R.rcx);
	f->R.rax = d->read_cnt;
}

static void
inspect_write_cnt(struct intr_frame *f)
{
	struct disk *d = disk_get(f->R.rdx, f->R.rcx);
	f->R.rax = d->write_cnt;
}

/* 디스크 읽기/쓰기 횟수 테스트용 도구입니다. 이 함수는 int 0x43 및 int 0x44를 통해 호출합니다.
 * 입력:
 *   @RDX - 검사할 디스크의 채널 번호
 *   @RCX - 검사할 디스크의 디바이스 번호
 * 출력:
 *   @RAX - 해당 디스크의 읽기/쓰기 횟수
 */
void register_disk_inspect_intr(void)
{
	intr_register_int(0x43, 3, INTR_OFF, inspect_read_cnt, "Inspect Disk Read Count");
	intr_register_int(0x44, 3, INTR_OFF, inspect_write_cnt, "Inspect Disk Write Count");
}
