Name:       nfc-manager
Summary:    NFC framework manager
Version:    0.0.52
Release:    0
Group:      libs
License:    Flora-1.1
Source0:    %{name}-%{version}.tar.gz
Source1:    libnfc-manager-0.init.in
Source2:    nfc-manager.service
Requires:   sys-assert
BuildRequires: pkgconfig(aul)
BuildRequires: pkgconfig(glib-2.0)
BuildRequires: pkgconfig(gobject-2.0)
BuildRequires: pkgconfig(security-server)
BuildRequires: pkgconfig(dbus-glib-1)
BuildRequires: pkgconfig(vconf)
BuildRequires: pkgconfig(dlog)
BuildRequires: pkgconfig(tapi)
BuildRequires: pkgconfig(ecore)
BuildRequires: pkgconfig(bluetooth-api)
BuildRequires: pkgconfig(mm-sound)
BuildRequires: pkgconfig(appsvc)
BuildRequires: pkgconfig(heynoti)
BuildRequires: pkgconfig(svi)
BuildRequires: pkgconfig(capi-media-wav-player)
BuildRequires: pkgconfig(smartcard-service)
BuildRequires: pkgconfig(smartcard-service-common)
BuildRequires: pkgconfig(libssl)
BuildRequires: pkgconfig(pmapi)
BuildRequires: pkgconfig(pkgmgr)
BuildRequires: pkgconfig(pkgmgr-info)
BuildRequires: pkgconfig(ecore-x)
BuildRequires: cmake
BuildRequires: gettext-tools
Requires(post):   /sbin/ldconfig
Requires(post):   /usr/bin/vconftool
requires(postun): /sbin/ldconfig


%description
NFC library Manager.


%prep
%setup -q


%package devel
Summary:    Download agent
Group:      Development/Libraries
Requires:   %{name} = %{version}-%{release}


%description devel
NFC library Manager (devel)


%package -n nfc-common-lib
Summary:    NFC common library
Group:      Development/Libraries
Requires:   %{name} = %{version}-%{release}


%description -n nfc-common-lib
NFC Common library.


%package -n nfc-common-lib-devel
Summary:    NFC common library (devel)
Group:      libs
Requires:   %{name} = %{version}-%{release}


%description -n nfc-common-lib-devel
NFC common library (devel)


%build
export LDFLAGS+="-Wl,--rpath=%{_libdir} -Wl,--as-needed"
mkdir cmake_tmp
cd cmake_tmp
LDFLAGS="$LDFLAGS" %cmake ..

make


%install
cd cmake_tmp
%make_install
cd ..
%__mkdir -p  %{buildroot}/etc/init.d/
%__cp -af %SOURCE1  %{buildroot}/etc/init.d/libnfc-manager-0
chmod 755 %{buildroot}/etc/init.d/libnfc-manager-0
mkdir -p %{buildroot}/usr/share/license
cp -af LICENSE.Flora %{buildroot}/usr/share/license/nfc-common-lib
cp -af LICENSE.Flora %{buildroot}/usr/share/license/%{name}-devel
cp -af LICENSE.Flora %{buildroot}/usr/share/license/nfc-common-lib-devel
cp -af LICENSE.Flora %{buildroot}/usr/share/license/%{name}

mkdir -p %{buildroot}/usr/lib/systemd/system/multi-user.target.wants
cp -af %{SOURCE2} %{buildroot}/usr/lib/systemd/system/
ln -s ../nfc-manager.service %{buildroot}/usr/lib/systemd/system/multi-user.target.wants/nfc-manager.service


%post
/sbin/ldconfig
vconftool set -t bool db/nfc/feature 1 -u 5000 -f
vconftool set -t bool db/nfc/enable 0 -u 5000 -f
vconftool set -t bool db/nfc/sbeam 0 -u 5000 -f
vconftool set -t int db/nfc/se_type 0 -u 5000 -f
vconftool set -t bool db/nfc/predefined_item_state 0 -u 5000 -f
vconftool set -t string db/nfc/predefined_item "None" -u 5000 -f

ln -s /etc/init.d/libnfc-manager-0 /etc/rc.d/rc3.d/S81libnfc-manager-0 -f
ln -s /etc/init.d/libnfc-manager-0 /etc/rc.d/rc5.d/S81libnfc-manager-0 -f

mkdir -p /opt/etc/nfc_debug
chown :5000 /opt/etc/nfc_debug
chmod 775 /opt/etc/nfc_debug

systemctl daemon-reload
if [ $1 == 1 ]; then
    systemctl restart nfc-manager.service
fi


%postun
/sbin/ldconfig
mkdir -p /etc/rc.d/rc3.d
mkdir -p /etc/rc.d/rc5.d
rm -f /etc/rc.d/rc3.d/S81libnfc-manager-0
rm -f /etc/rc.d/rc5.d/S81libnfc-manager-0

if [ $1 == 0 ]; then
    systemctl stop nfc-manager.service
fi
systemctl daemon-reload


%post -n nfc-common-lib -p /sbin/ldconfig


%postun -n nfc-common-lib -p /sbin/ldconfig


%files
%manifest nfc-manager.manifest
%defattr(-,root,root,-)
%{_libdir}/libnfc.so.1
%{_libdir}/libnfc.so.1.0.0
%{_prefix}/bin/nfc-manager-daemon
%{_prefix}/bin/ndef-tool
/etc/init.d/libnfc-manager-0
%{_datadir}/dbus-1/services/org.tizen.nfc_service.service
/usr/share/license/%{name}
/usr/lib/systemd/system/nfc-manager.service
/usr/lib/systemd/system/multi-user.target.wants/nfc-manager.service


%files devel
%manifest nfc-manager-devel.manifest
%defattr(-,root,root,-)
%{_libdir}/pkgconfig/nfc.pc
%{_includedir}/nfc/*.h
%{_libdir}/libnfc.so
/usr/share/license/%{name}-devel


%files -n nfc-common-lib
%manifest nfc-common-lib.manifest
%defattr(-,root,root,-)
%{_libdir}/libnfc-common-lib.so.1
%{_libdir}/libnfc-common-lib.so.1.0.0
/usr/share/license/nfc-common-lib
/usr/share/nfc-manager-daemon/sounds/*


%files -n nfc-common-lib-devel
%manifest nfc-common-lib-devel.manifest
%defattr(-,root,root,-)
%{_libdir}/libnfc-common-lib.so
%{_libdir}/pkgconfig/nfc-common-lib.pc
%{_includedir}/nfc-common-lib/*.h
/usr/share/license/nfc-common-lib-devel
