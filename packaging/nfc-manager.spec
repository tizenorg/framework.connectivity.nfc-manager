Name:       nfc-manager
Summary:    NFC framework manager
Version:    0.1.78
Release:    0
Group:      libs
License:    Flora Software License
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
BuildRequires: pkgconfig(mm-sound)
BuildRequires: pkgconfig(appsvc)
BuildRequires: pkgconfig(feedback)
BuildRequires: pkgconfig(capi-media-wav-player)
BuildRequires: pkgconfig(libssl)
BuildRequires: pkgconfig(deviced)
BuildRequires: pkgconfig(pkgmgr)
BuildRequires: pkgconfig(pkgmgr-info)
BuildRequires: pkgconfig(ecore-x)
BuildRequires: pkgconfig(mm-keysound)
BuildRequires: pkgconfig(syspopup-caller)
BuildRequires: pkgconfig(notification)
BuildRequires: pkgconfig(capi-network-wifi)
BuildRequires: pkgconfig(capi-network-wifi-direct)
BuildRequires: pkgconfig(capi-system-info)
BuildRequires: python
BuildRequires: python-xml
Requires(post):   /sbin/ldconfig
Requires(post):   /usr/bin/vconftool
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

export LDFLAGS+="-Wl,--rpath=%{_prefix}/lib -Wl,--as-needed"
LDFLAGS="$LDFLAGS" cmake . \
		-DTIZEN_ENGINEER_MODE=1 \
		-DCMAKE_INSTALL_PREFIX=%{_prefix}

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

mkdir -p /opt/usr/share/nfc_debug
chown :5000 /opt/usr/share/nfc_debug
chmod 775 /opt/usr/share/nfc_debug

mkdir -p /opt/usr/share/nfc-manager-daemon
chown :5000 /opt/usr/share/nfc-manager-daemon
chmod 775 /opt/usr/share/nfc-manager-daemon

mkdir -p -m 755 /opt/usr/share/nfc-manager-daemon/message
chown :5000 /opt/usr/share/nfc-manager-daemon/message

systemctl daemon-reload
if [ $1 == 1 ]; then
    systemctl restart %{name}.service
fi


%post -n nfc-client-lib
/sbin/ldconfig
vconftool set -t bool db/nfc/feature 0 -u 5000 -f -s system::vconf_network
vconftool set -t bool db/nfc/predefined_item_state 0 -u 5000 -f -s nfc-manager
vconftool set -t string db/nfc/predefined_item "None" -u 5000 -f -s nfc-manager

vconftool set -t bool db/nfc/enable 1 -u 5000 -f -s system::vconf_network
vconftool set -t int db/nfc/se_type 3 -u 5000 -f -s nfc-manager
vconftool set -t int db/nfc/wallet_mode 0 -u 5000 -f -s nfc-manager
vconftool set -t bool db/nfc/state_by_flight 0 -u 5000 -f -s system::vconf_network


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
%if 0%{?tizen_build_binary_release_type_eng}
%{_bindir}/ndef-tool
#%{_bindir}/nfc_client
%endif
%{_libdir}/systemd/system/%{name}.service
%{_libdir}/systemd/system/multi-user.target.wants/%{name}.service
%{_datadir}/dbus-1/services/org.tizen.NetNfcService.service
%{_datadir}/license/%{name}
%{_datadir}/packages/%{name}.xml


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
