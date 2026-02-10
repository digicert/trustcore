#!/bin/bash
# ----------------------------------------------------------------------
#  Run this script from the <git-repo>/src directory, and specify
#  the desired Doxygen config file as a relative path:
#  ../doxygen/make/<ref>/moc_doxygen ../doxygen/make/Doxyfile.<ref>
#  This relativity is needed so that Doxygen doesn't include any part
#  of a user's path in the filename/filepath info it outputs.
# ----------------------------------------------------------------------

# ----------------------------------------------------------------------
#  Clean the Doxygen output folders, because Doxygen doesn't do that
#  for you. And if you don't do this, you could end up with old PDFs and
#  per http://sourceforge.net/p/doxygen/mailman/message/27186280/, old
#  HTML for classes that are no longer applicable.
# ----------------------------------------------------------------------
#rmdir ..\doxygen\output\$1 /s /Q
OUTPATH=../doxygen/output/$1
rm -rf $OUTPATH
mkdir -p $OUTPATH

# ----------------------------------------------------------------------
#  Invoke Doxygen.
# ----------------------------------------------------------------------
doxygen ../doxygen/make/Doxyfile.$1

# ----------------------------------------------------------------------
#  Copy the Product/User Guide PDFs to where they're needed.
#  The output folder depends on the OUTPUT_DIRECTORY config option in
#  the Doxyfile configuration file.
# ----------------------------------------------------------------------
if [ ! -d ../$OUTPATH/html/pdfs ]; then
mkdir -p $OUTPATH/html/pdfs
fi
if [ -d ../doxygen/make/pdfs/common ]; then
cp -Rfv ../doxygen/make/pdfs/common $OUTPATH/html/pdfs/
fi
if [ -d ../doxygen/make/pdfs/$1 ]; then
cp -Rfv ../doxygen/make/pdfs/$1 $OUTPATH/html/pdfs/
fi

# ----------------------------------------------------------------------
#  Copy the images to where they're needed (which is hardcoded in the
#  Doxygen-comment blocks). Ideally of course we'd use Doxygen's @image
#  command, but that's not working for putting images in html <table>
#  elements. So this is a work-around.
# ----------------------------------------------------------------------
if [ ! -d ../$OUTPATH/html/images ]; then
mkdir -p $OUTPATH/html/images
fi
if [ -d ../doxygen/make/images/common ]; then
cp -Rfv ../doxygen/make/images/common $OUTPATH/html/images/
fi
if [ -d ../doxygen/make/images/$1 ]; then
cp -Rfv ../doxygen/make/images/$1 $OUTPATH/html/images/
fi

# ----------------------------------------------------------------------
#  Copy images from other products to NanoTAP output
# ----------------------------------------------------------------------
if [[ "$1" -eq nanotap12 ]]; then
cp ../doxygen/make/images/nanocrypto/flowchart_rsa.jpg $OUTPATH/html/images/
fi
if [[ "$1" -eq nanotap ]]; then
cp ../doxygen/make/images/nanocrypto/flowchart_rsa.jpg $OUTPATH/html/images/
fi
