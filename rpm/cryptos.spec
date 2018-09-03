Name: cryptos
Version: 0.1.0
Release: 1
Group: System/Libraries
License: Proprietary
Source: %{name}-%{version}.tar.bz2
Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig
Requires: libsailfishsecrets
BuildRequires: libsailfishsecrets-devel

Summary: Various requests to sailfish api

%{!?qtc_qmake:%define qtc_qmake %qmake}
%{!?qtc_qmake5:%define qtc_qmake5 %qmake5}
%{!?qtc_make:%define qtc_make make}
%{?qtc_builddir:%define _builddir %qtc_builddir}

%description
Manage iptables rules with Sailfish Connman iptables management plugin (allow and deny ip addresses)

%prep
%setup -q -n %{name}-%{version}

%build
%qtc_qmake5
%qtc_make %{?_smp_mflags}

%install
rm -rf %{buildroot}
%qmake5_install

%files
%defattr(-,root,root,-)
%{_bindir}/%{name}
