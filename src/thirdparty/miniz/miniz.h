/*
 * miniz.h — stub for platforms without ZIP support (e.g. Azure RTOS / ThreadX).
 *
 * TRUSTEDGE_utilsExtractInlineZip() in trustedge_utils.c uses the miniz API to
 * extract ZIP archives.  That function is never called on bare-metal RTOS
 * targets, but it must compile.  These stub inline functions return failure
 * immediately, satisfying the compiler without pulling in the real miniz library.
 */

#ifndef MINIZ_STUB_H
#define MINIZ_STUB_H

typedef int mz_bool;
typedef int mz_zip_error;

#define MZ_ZIP_FLAG_CASE_SENSITIVE 0x0100

typedef struct {
    unsigned char m_filename[260];
    int           m_is_directory;
    int           m_is_supported;
} mz_zip_archive_file_stat;

typedef struct {
    void *m_reserved;
} mz_zip_archive;

static inline mz_bool mz_zip_reader_init_file_v2(
        mz_zip_archive *pZip, const char *pFilename, unsigned flags,
        unsigned long long file_start_ofs, unsigned long long archive_size)
{
    (void)pZip; (void)pFilename; (void)flags;
    (void)file_start_ofs; (void)archive_size;
    return 0; /* always fail — ZIP extraction not supported on this platform */
}

static inline const char *mz_zip_get_error_string(mz_zip_error mz_err)
{ (void)mz_err; return "zip not supported"; }

static inline mz_zip_error mz_zip_get_last_error(mz_zip_archive *pZip)
{ (void)pZip; return 0; }

static inline unsigned int mz_zip_reader_get_num_files(mz_zip_archive *pZip)
{ (void)pZip; return 0; }

static inline mz_bool mz_zip_reader_file_stat(
        mz_zip_archive *pZip, unsigned file_index, mz_zip_archive_file_stat *pStat)
{ (void)pZip; (void)file_index; (void)pStat; return 0; }

static inline mz_bool mz_zip_reader_extract_file_to_file(
        mz_zip_archive *pZip, const char *pArchive_filename,
        const char *pDst_filename, unsigned flags)
{ (void)pZip; (void)pArchive_filename; (void)pDst_filename; (void)flags; return 0; }

static inline void mz_zip_reader_end(mz_zip_archive *pZip)
{ (void)pZip; }

#endif /* MINIZ_STUB_H */
