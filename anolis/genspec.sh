#! /bin/bash
# generate kernel spec through spec template and changelog files.
# it it call from Makefile, do not run it directly.

mkdir -p ${DIST_OUTPUT}
cp -f ${DIST_RPM}/${DIST_SPEC_TEMPLATE} ${DIST_OUTPUT}/${DIST_SPEC_FILE}

for changelog_file in $(ls ${DIST_CHANGELOG} | sort)
do
    sed -i "/%changelog/r ${DIST_CHANGELOG}/${changelog_file}" ${DIST_OUTPUT}/${DIST_SPEC_FILE}
done

sed -i -e "
    s/%%DIST%%/$DIST/
    s/%%DIST_KERNELVERSION%%/$DIST_KERNELVERSION/
    s/%%DIST_PKGRELEASEVERION%%/$DIST_PKGRELEASEVERION/" ${DIST_OUTPUT}/${DIST_SPEC_FILE}