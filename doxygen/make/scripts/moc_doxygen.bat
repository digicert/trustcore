@echo
rem     * TODO: This file is not in sync with the .sh version and should be modified.
rem     * 
rem     * Invoke this batch file from the <git-repo>\src directory, and specify
rem     * the desired Doxygen config file as a relative path:
rem     * ..\doxygen\make\<ref>\moc_doxygen ..\doxygen\make\Doxyfile.<ref>
rem     * This relativity is needed so that Doxygen doesn't include any part
rem     * of a user's path in the filename/filepath info it outputs.

rem     * Clean the Doxygen output folders, because Doxygen doesn't do that
rem     * for you. And if you don't do this, you could end up with old PDFs and
rem     * per http://sourceforge.net/p/doxygen/mailman/message/27186280/, old
rem     * HTML for classes that are no longer applicable.
rmdir ..\doxygen\output\%1 /s /Q

rem     Invoke Doxygen.
doxygen ..\doxygen\make\Doxyfile.%1

rem     * Copy the Product/User Guide PDFs to where they're needed.
rem     * The output folder depends on the OUTPUT_DIRECTORY config option in
rem     * the Doxyfile configuration file.
xcopy /i /y ..\doxygen\make\pdfs\common ..\doxygen\output\%1\html\pdfs
xcopy /i /y ..\doxygen\make\pdfs\%1 ..\doxygen\output\%1\html\pdfs

rem     * Copy the images to where they're needed (which is hardcoded in the
rem     * Doxygen-comment blocks). Ideally of course we'd use Doxygen's @image
rem     * command, but that's not working for putting images in html <table>
rem     * elements. So this is a work-around.
xcopy /i /y ..\doxygen\make\images\common ..\doxygen\output\%1\html\images
xcopy /i /y ..\doxygen\make\images\%1 ..\doxygen\output\%1\html\images
