#ifdef _USER_MODE
#define	chprio  xinu_chprio
#define	close   xinu_close
#define	control xinu_control
#define	freebuf xinu_freebuf
#define	freemem xinu_freemem
#define	getc    xinu_getc
#define	getprio xinu_getprio
#define	init    xinu_init
#define	kill    xinu_kill
#define	mount   xinu_mount
#define	open    xinu_open
#define	ptcreate    xinu_ptcreate
#define	ptdelete    xinu_ptdelete
#define	ptinit  xinu_ptinit
#define	ptreset xinu_ptreset
#define	ptsend  xinu_ptsend
#define	putc    xinu_putc
#define	rdsars  xinu_rdsars
#define	read    xinu_read
#define	resume  xinu_resume
#define	seek    xinu_seek
#define	semcount    xinu_semcount
#define	semdelete   xinu_semdelete
#define	semreset    xinu_semreset
#define	send    xinu_send
#define	signal  xinu_signal
#define	signaln xinu_signaln
#define	sleepms xinu_sleepms
#define	sleep   xinu_sleep
#define	suspend xinu_suspend
#define	unsleep xinu_unsleep
#define	wait    xinu_wait
#define	write   xinu_write
#define	yield   xinu_yield
#endif
