#ifndef EXTERNAL_RAND_THREAD_H
#define EXTERNAL_RAND_THREAD_H
MOC_EXTERN MSTATUS DIGICERT_waitForExternalEntropy (void);
MOC_EXTERN MSTATUS DIGICERT_cancelExternalEntropy (void);
MOC_EXTERN MSTATUS DIGICERT_addExternalEntropyThread (void);
MOC_EXTERN MSTATUS DIGICERT_addExternalEntropy (int async);
MOC_EXTERN MSTATUS DIGICERT_addExternalEntropyThreadWait (void);
#endif
