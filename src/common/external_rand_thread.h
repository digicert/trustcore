#ifndef EXTERNAL_RAND_THREAD_H
#define EXTERNAL_RAND_THREAD_H
MOC_EXTERN MSTATUS MOCANA_waitForExternalEntropy (void);
MOC_EXTERN MSTATUS MOCANA_cancelExternalEntropy (void);
MOC_EXTERN MSTATUS MOCANA_addExternalEntropyThread (void);
MOC_EXTERN MSTATUS MOCANA_addExternalEntropy (int async);
MOC_EXTERN MSTATUS MOCANA_addExternalEntropyThreadWait (void);
#endif
