# $Header: /home/jakubs/DEV/jnettop-conversion/jnettop/jnettop.spec,v 1.3 2002-08-31 17:15:03 merunka Exp $

Summary: Network traffic tracker
Name: jnettop
Version: 0.3
Release: 1
Group: Network/Monitoring
License: GNU
Source: http://www.kubs.cz/jnettop/dist/jnettop-%{version}.tar.gz
Buildroot: %{_tmppath}/%{name}-root

%description
Nettop is visualising active network traffic as top does with processes.
It displays active network streams sorted by bandwidth used. This is
often usable when you want to get a fast grip of what is going on on your
outbound router.

%prep
%setup -q
find . -type d -name CVS |xargs rm -rf

%build
export CFLAGS="$RPM_OPT_FLAGS"
%configure 
make

%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT

%clean
rm -r $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
%{_bindir}/jnettop
%doc AUTHORS ChangeLog COPYING INSTALL NEWS README

%changelog
* Thu Aug 27 2002 Jakub Skopal <j@kubs.cz> 0.3-1
- transition to release 0.3, see ChangeLog

* Thu Aug 27 2002 Jakub Skopal <j@kubs.cz> 0.2-1
- transition to release 0.2, see ChangeLog

* Thu Aug 22 2002 Jakub Skopal <j@kubs.cz> 0.1-1
- initial release

