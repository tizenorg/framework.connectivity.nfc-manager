Name:       nfc-manager
Summary:    NFC framework manager
Version:    0.1.103
Release:    0
Group:      libs
License:    Flora-1.1
Source0:    %{name}-%{version}.tar.gz
Source1:    nfc-manager.service
Requires:   sys-assert
BuildRequires: cmake
BuildRequires: pkgconfig(aul)
BuildRequires: pkgconfig(glib-2.0)
BuildRequires: pkgconfig(gobject-2.0)
BuildRequires: pkgconfig(security-server)
BuildRequires: pkgconfig(vconf)
BuildRequires: pkgconfig(dlog)
BuildRequires: pkgconfig(tapi)
BuildRequires: pkgconfig(bluetooth-api)
BuildRequires: pkgconfig(capi-network-bluetooth)
BuildRequires: pkgconfig(mm-sound)
BuildRequires: pkgconfig(appsvc)
BuildRequires: pkgconfig(feedback)
BuildRequires: pkgconfig(capi-media-wav-player)
BuildRequires: pkgconfig(openssl)
BuildRequires: pkgconfig(deviced)
BuildRequires: pkgconfig(ecore-x)
BuildRequires: pkgconfig(mm-keysound)
BuildRequires: pkgconfig(syspopup-caller)
BuildRequires: pkgconfig(notification)
BuildRequires: pkgconfig(capi-network-wifi)
BuildRequires: pkgconfig(capi-network-wifi-direct)
BuildRequires: pkgconfig(capi-system-info)
BuildRequires: pkgconfig(sqlite3)
BuildRequires: pkgconfig(pkgmgr-info)
BuildRequires: pkgconfig(libxml-2.0)
BuildRequires: pkgconfig(libcurl)
BuildRequires: pkgconfig(libprivilege-control)
BuildRequires: python
BuildRequires: python-xml
Requires(postun): /sbin/ldconfig


%description
NFC library Manager.


%prep
%setup -q


%package -n nfc-common-lib
Summary:    NFC common library
Group:      Development/Libraries


%description -n nfc-common-lib
NFC Common library.


%package -n nfc-common-lib-devel
Summary:    NFC common library (devel)
Group:      libs
Requires:   nfc-common-lib = %{version}-%{release}


%description -n nfc-common-lib-devel
NFC common library (devel)


%package -n nfc-client-lib
Summary:    NFC client library
Group:      Development/Libraries
Requires:   nfc-common-lib = %{version}-%{release}


%description -n nfc-client-lib
NFC Client library.


%package -n nfc-client-lib-devel
Summary:    NFC client library (devel)
Group:      libs
Requires:   nfc-client-lib = %{version}-%{release}


%description -n nfc-client-lib-devel
NFC client library (devel)


#%%package -n nfc-client-test
#Summary:    NFC client test
#Group:      Development/Libraries
#Requires:   %{name} = %{version}-%{release}
#
#
#%%description -n nfc-client-test
#NFC client test (devel)


%build
export CFLAGS="$CFLAGS -DTIZEN_DEBUG_ENABLE"
export CXXFLAGS="$CXXFLAGS -DTIZEN_DEBUG_ENABLE"
export FFLAGS="$FFLAGS -DTIZEN_DEBUG_ENABLE"
export CFLAGS="$CFLAGS -DTIZEN_TELEPHONY_ENABLED"

export LDFLAGS+="-Wl,--rpath=%{_prefix}/lib -Wl,--as-needed"
LDFLAGS="$LDFLAGS" cmake . \
		-DTIZEN_ENGINEER_MODE=1 \
		-DCMAKE_INSTALL_PREFIX=%{_prefix} \
		-DTIZEN_TELEPHONY_ENABLED=1 \

%install
%make_install

mkdir -p %{buildroot}%{_libdir}/systemd/system/multi-user.target.wants
cp -af %{SOURCE1} %{buildroot}%{_libdir}/systemd/system/

mkdir -p %{buildroot}%{_libdir}/systemd/system/multi-user.target.wants
ln -s ../%{name}.service %{buildroot}%{_libdir}/systemd/system/multi-user.target.wants/%{name}.service

install -D -m 0644 LICENSE.Flora  %{buildroot}/%{_datadir}/license/nfc-common-lib
install -D -m 0644 LICENSE.Flora  %{buildroot}/%{_datadir}/license/%{name}
install -D -m 0644 LICENSE.Flora  %{buildroot}/%{_datadir}/license/nfc-client-lib
#install -D -m 0644 LICENSE.Flora  %{buildroot}/%{_datadir}/license/nfc-client-test


%post
/sbin/ldconfig

mkdir -p -m 700 /opt/usr/data/nfc-manager-daemon
/usr/bin/chsmack -a nfc-manager /opt/usr/data/nfc-manager-daemon
chown system:system /opt/usr/data/nfc-manager-daemon

mkdir -p -m 744 /opt/usr/share/nfc_debug
/usr/bin/chsmack -a nfc-manager /opt/usr/share/nfc_debug
chown system:system /opt/usr/share/nfc_debug

mkdir -p -m 744 /opt/usr/share/nfc-manager-daemon
/usr/bin/chsmack -a nfc-manager /opt/usr/share/nfc-manager-daemon
chown system:system /opt/usr/share/nfc-manager-daemon

mkdir -p -m 744 /opt/usr/share/nfc-manager-daemon/message
/usr/bin/chsmack -a nfc-manager /opt/usr/share/nfc-manager-daemon/message
chown system:system /opt/usr/share/nfc-manager-daemon/message

systemctl daemon-reload
if [ $1 == 1 ]; then
    systemctl restart %{name}.service
fi


%post -n nfc-client-lib

/usr/sbin/setcap cap_mac_override+ep /usr/bin/nfc-manager-daemon

%postun
/sbin/ldconfig

if [ $1 == 0 ]; then
    systemctl stop %{name}.service
fi
systemctl daemon-reload


%post -n nfc-common-lib -p /sbin/ldconfig


%postun -n nfc-common-lib -p /sbin/ldconfig


%files
%manifest %{name}.manifest
%defattr(-,root,root,-)
%{_bindir}/nfc-manager-daemon
#%{_bindir}/nfc_client
%{_libdir}/systemd/system/%{name}.service
%{_libdir}/systemd/system/multi-user.target.wants/%{name}.service
%{_datadir}/dbus-1/system-services/org.tizen.NetNfcService.service
%{_datadir}/license/%{name}


%files -n nfc-client-lib
%manifest nfc-client-lib.manifest
%defattr(-,root,root,-)
%{_libdir}/libnfc.so
%{_libdir}/libnfc.so.*
%{_datadir}/license/nfc-client-lib


%files -n nfc-client-lib-devel
%manifest nfc-client-lib-devel.manifest
%defattr(-,root,root,-)
%{_libdir}/pkgconfig/nfc.pc
%{_includedir}/nfc/*.h


%files -n nfc-common-lib
%manifest nfc-common-lib.manifest
%defattr(-,root,root,-)
%{_libdir}/libnfc-common-lib.so
%{_libdir}/libnfc-common-lib.so.*
/usr/etc/package-manager/parserlib/metadata/libcardemulation_plugin.so
%{_datadir}/license/nfc-common-lib
%{_datadir}/nfc-manager-daemon/sounds/Operation_sdk.wav


%files -n nfc-common-lib-devel
%manifest nfc-common-lib-devel.manifest
%defattr(-,root,root,-)
%{_libdir}/pkgconfig/nfc-common-lib.pc
%{_includedir}/nfc-common-lib/*.h


#%%files -n nfc-client-test
#%%manifest nfc-client-test.manifest
#%%defattr(-,root,root,-)
#%%{_bindir}/nfc_client
#%%{_datadir}/license/nfc-client-test
