# Copyright 2023 Hewlett Packard Enterprise Development LP
%define release_extra SHS11.0.0

%{!?dkms_source_tree:%define dkms_source_tree /usr/src}

%if 0%{?rhel}
%define distro_kernel_package_name kmod-%{name}
%else
%define distro_kernel_package_name %{name}-kmp
%endif

# Exclude -preempt kernel flavor, this seems to get built alongside the -default
# flavor for stock SLES. It doesn't get used, and its presence can cause issues
# (see NETCASSINI-4032)
%define kmp_args_common -x preempt -p %{_sourcedir}/%name.rpm_preamble

%if 0%{?rhel}
# On RHEL, override the kmod RPM name to include the kernel version it was built
# for; this allows us to package the same driver for multiple kernel versions.
%define kmp_args -n %name-k%%kernel_version %kmp_args_common
%else
%define kmp_args %kmp_args_common
%endif

Name:           kdreg2
Version:        1.0.0
Release:        %(echo ${BUILD_METADATA})
Summary:        HPE Kdreg2 kernel memory monitor module
License:        GPL-2.0
Source0:        %{name}-%{version}.tar.gz
Prefix:         /usr

BuildRequires:  %kernel_module_package_buildreqs

# Generate a preamble that gets attached to the kmod RPM(s). Kernel module
# dependencies can be declared here. The 'Obsoletes' and 'Provides' lines for
# RHEL allow the package to be referred to by its base name without having to
# explicitly specify a kernel version.
%(/bin/echo -e "\
%if 0%%{?rhel} \n\
Obsoletes:      kmod-%%{name} \n\
Provides:       kmod-%%{name} = %%version-%%release \n\
%endif" > %{_sourcedir}/%{name}.rpm_preamble)

%if 0%{with shasta_premium}
# The nvidia-gpu-build-obs package (necessary for building against CUDA
# drivers) causes a bogus default kernel flavor to be added. This causes
# builds to fail, as upstream dependencies (i.e. SBL) are not built for
# default on shasta-premium. Work around this by explicitly excluding the
# default flavor on shasta-premium
%kernel_module_package -x default %kmp_args
%else
%kernel_module_package %kmp_args
%endif

%description
Kdreg2 memory monitor kernel module

%package devel
Summary:    Development files for Kdreg2 memory monitor

%description devel
Development files for Kdreg2 memory monitor

%package dkms
Summary:        DKMS support for %{name} kernel modules
Requires: 	dkms
Requires:	kdreg2
Conflicts:      %{distro_kernel_package_name}
BuildArch: 	noarch

%description dkms
DKMS support for %{name} kernel modules

%prep
%setup

set -- *
mkdir source
mv "$@" source/
mkdir obj

%build
for flavor in %flavors_to_build; do
    rm -rf obj/$flavor
    cp -r source obj/$flavor
    make -C obj/$flavor build_info
    make -C obj/$flavor/config all KDIR=%{kernel_source $flavor}
    make -C %{kernel_source $flavor} modules M=$PWD/obj/$flavor
done

%install
export INSTALL_MOD_PATH=$RPM_BUILD_ROOT
export INSTALL_MOD_DIR=extra
for flavor in %flavors_to_build; do
    make -C %{kernel_source $flavor} modules_install M=$PWD/obj/$flavor
    install -m 644 -D --target-directory=$RPM_BUILD_ROOT%{prefix}/src/kdreg2/$flavor $PWD/obj/$flavor/Module.symvers
done

install -m 644 -D --target-directory=%{buildroot}%{_includedir}/linux source/include/kdreg2.h

%if 0%{?rhel}
# Centos/Rocky/RHEL does not exclude the depmod-generated modules.* files from
# the RPM, causing file conflicts when updating
find $RPM_BUILD_ROOT -iname 'modules.*' -exec rm {} \;
%endif

# DKMS addition
dkms_source_dir=%{dkms_source_tree}/%{name}-%{version}-%{release}
mkdir -p %{buildroot}/${dkms_source_dir}
cp -r source/* %{buildroot}/${dkms_source_dir}

echo "%dir ${dkms_source_dir}" > dkms-files
echo "${dkms_source_dir}" >> dkms-files

sed\
  -e '/^$/d'\
  -e '/^#/d'\
  -e 's/@PACKAGE_NAME@/%{name}/g'\
  -e 's/@PACKAGE_VERSION@/%{version}-%{release}/g'\
\
  %{buildroot}${dkms_source_dir}/dkms.conf.in > %{buildroot}${dkms_source_dir}/dkms.conf
rm -f %{buildroot}${dkms_source_dir}/dkms.conf.in

%pre dkms

%post dkms
if [ -f /usr/libexec/dkms/common.postinst ] && [ -x /usr/libexec/dkms/common.postinst ]
then
    postinst=/usr/libexec/dkms/common.postinst
elif [ -f /usr/lib/dkms/common.postinst ] && [ -x /usr/lib/dkms/common.postinst ]
then
    postinst=/usr/lib/dkms/common.postinst
else
    echo "ERROR: did not find DKMS common.postinst"
    exit 1
fi
${postinst} %{name} %{version}-%{release}

%preun dkms
#
# `dkms remove` may return an error but that should stop the package from
# being removed.   The " || true" ensures this command line always returns
# success.   One reason `dkms remove` may fail is if someone (an admin)
# already manually removed this dkms package.  But there are some other
# "soft errors" (supposedly) that should not prevent the dkms package
# from being removed.
#
/usr/sbin/dkms remove -m %{name} -v %{version}-%{release} --all --rpm_safe_upgrade || true
rm -f %{_modulesloaddir}/%{name}.conf || true

%post
# create module directory if necessary
if [ ! -d %{_modulesloaddir} ]
then
	mkdir -p %{_modulesloaddir}
fi

# Create the systemd load file
if [ ! -f %{_modulesloaddir}/%{name}.conf ]
then
    echo %{name} > %{_modulesloaddir}/%{name}.conf
    chmod 644 %{_modulesloaddir}/%{name}.conf
fi

%preun
rm -f %{_modulesloaddir}/%{name}.conf || true


%files

%files devel
%{_includedir}/linux/kdreg2.h
%{prefix}/src/kdreg2/*/Module.symvers

%files dkms -f dkms-files

%changelog
