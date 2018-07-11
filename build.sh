#! /bin/bash

log() {
    printf "\e[93m${1}\e[39m\n"
}
logerror() {
    printf "\e[91m${1}\e[39m\n"
}

HOMEDIR=`pwd`

ASTERISK_DOWNLOAD_BASE=http://downloads.asterisk.org/pub/telephony/asterisk/old-releases
ASTERISK_VERSION="13.21.1"
ASTERISK_ARCHIVE=asterisk-${ASTERISK_VERSION}.tar.gz
ASTERISK_DIR=asterisk-${ASTERISK_VERSION}

LIBDFEGRPC_BRANCH="master"

WORKDIR=/tmp

if [ ! -e ${WORKDIR}/libdfegrpc ] ; then
    printf "\e[93mCloning libdfegrpc...\e[39m\n"

    if grep centos /etc/os-release ; then 
        sudo yum install -y git
    elif grep ubuntu /etc/os-release ; then
        sudo apt-get install -y git
    else
        logerror "I don't know how to build on this OS"
        exit 1
    fi

    pushd ${WORKDIR}

    git clone https://github.com/USAN/libdfegrpc.git

    pushd libdfegrpc

    git checkout ${LIBDFEGRPC_BRANCH}
    bash ./install_protoc.sh

    make
    sudo make install
    sudo ldconfig

    popd

    popd
else
    printf "\e[93mlibdfegrpc already installed.\e[39m\n"
fi

if [ ! -e ${WORKDIR}/${ASTERISK_ARCHIVE} ] ; then
    printf "\e[93mDownloading asterisk...\e[39m\n"

    pushd ${WORKDIR}
    wget "${ASTERISK_DOWNLOAD_BASE}/${ASTERISK_ARCHIVE}"
    popd
else
    printf "\e[93mAsterisk ${ASTERISK_VERSION} already downloaded\e[39m\n"
fi

if [ ! -e ${WORKDIR}/${ASTERISK_DIR} ] ; then
    printf "\e[93mUnpacking Asterisk...\e[39m\n"

    tar -v -x -z -f "${WORKDIR}/asterisk-${ASTERISK_VERSION}.tar.gz" -C ${WORKDIR}

    printf "\e[93mChecking pre-requisites...\e[39m\n"

    sudo ${WORKDIR}/${ASTERISK_DIR}/contrib/scripts/install_prereq install
else
    printf "\e[93mAsterisk ${ASTERISK_VERSION} already unpacked\e[39m\n"
fi

BOOTSTRAP=0

# cp -v res_speech_gdfe.c ${WORKDIR}/${ASTERISK_DIR}/res/res_speech_gdfe.c
rsync -avz res/ ${WORKDIR}/${ASTERISK_DIR}/res/

if grep PBX_DFEGRPC ${WORKDIR}/${ASTERISK_DIR}/build_tools/menuselect-deps.in > /dev/null ; then
    printf "\e[93mMenuselect-deps.in already modified\e[39m\n"
else
    printf "\e[93mModifying Menuselect-deps.in\e[39m\n"
    printf "\nDFEGRPC=@PBX_DFEGRPC@\n" >> ${WORKDIR}/${ASTERISK_DIR}/build_tools/menuselect-deps.in
    BOOTSTRAP=1
fi

if grep DFEGRPC_INCLUDE ${WORKDIR}/${ASTERISK_DIR}/makeopts.in > /dev/null ; then
    printf "\e[93mmakeopts.in already modified\e[39m\n"
else
    printf "\e[93mModifying makeopts.in\e[39m\n"
    printf "\nDFEGRPC_INCLUDE=@DFEGRPC_INCLUDE@\nDFEGRPC_LIB=@DFEGRPC_LIB@\n" >> ${WORKDIR}/${ASTERISK_DIR}/makeopts.in
    BOOTSTRAP=1
fi

if grep DFEGRPC ${WORKDIR}/${ASTERISK_DIR}/configure.ac > /dev/null ; then
    printf "\e[93mconfigure.ac already modified\e[39m\n"
else
    printf "\e[93mPatching configure.ac\e[39m\n"
    pushd ${WORKDIR}/${ASTERISK_DIR}
    patch -p0 < ${HOMEDIR}/configure.ac.diff
    popd
    BOOTSTRAP=1
fi

if [ X"${BOOTSTRAP}" = X"1" ] ; then 
    printf "\e[93mBootstrapping asterisk\e[39m\n"
    pushd ${WORKDIR}/${ASTERISK_DIR}
    ./bootstrap.sh
    popd
    rm -f ${WORKDIR}/${ASTERISK_DIR}/makeopts
fi

if [ ! -e ${WORKDIR}/${ASTERISK_DIR}/makeopts ]; then 
    printf "\e[93mRunning configure...\e[39m\n"

    pushd ${WORKDIR}/${ASTERISK_DIR}

    ./configure --with-pjproject-bundled

    popd
else 
    printf "\e[93mAsterisk configured...\e[39m\n"
fi

printf "\e[93mRunning make...\e[39m\n"
pushd ${WORKDIR}/${ASTERISK_DIR}
make NOISY_BUILD=yes && sudo make install
popd

sudo cp -v config/* /etc/asterisk/
if [ ! -e /etc/asterisk/svc_key.json ]; then
    cat << EOF > /tmp/svc_key.json
${SVC_KEY}
EOF
    sudo cp -v /tmp/svc_key.json /etc/asterisk/
fi
