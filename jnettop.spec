# $Header: /home/jakubs/DEV/jnettop-conversion/jnettop/jnettop.spec,v 1.11 2004-09-29 19:09:35 merunka Exp $

Summary: Network traffic tracker
Name: jnettop
Version: 0.10
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
%{_mandir}/man8/jnettop.8.gz
%doc AUTHORS ChangeLog COPYING INSTALL NEWS README .jnettop

%changelog
* Wed Sep 29 2004 Jakub Skopal <j@kubs.cz> 0.10
- manual page is now part of RPM package
- transition to release 0.10, see ChangeLog

* Wed Jul 30 2003 Jakub Skopal <j@kubs.cz> 0.9
- transition to release 0.9, see ChangeLog

* Wed Apr 23 2003 Jakub Skopal <j@kubs.cz> 0.8.1-1
- transition to release 0.8.1, see ChangeLog

* Wed Apr 23 2003 Jakub Skopal <j@kubs.cz> 0.8-1
- transition to release 0.8, see ChangeLog

* Tue Oct 16 2002 Jakub Skopal <j@kubs.cz> 0.7-1
- transition to release 0.7, see ChangeLog

* Tue Oct 13 2002 Jakub Skopal <j@kubs.cz> 0.6-1
- transition to release 0.6, see ChangeLog

* Tue Sep 03 2002 Jakub Skopal <j@kubs.cz> 0.5-1
- transition to release 0.5, see ChangeLog

* Mon Sep 02 2002 Jakub Skopal <j@kubs.cz> 0.4-1
- transition to release 0.4, see ChangeLog

* Thu Aug 27 2002 Jakub Skopal <j@kubs.cz> 0.3-1
- transition to release 0.3, see ChangeLog

* Thu Aug 27 2002 Jakub Skopal <j@kubs.cz> 0.2-1
- transition to release 0.2, see ChangeLog

* Thu Aug 22 2002 Jakub Skopal <j@kubs.cz> 0.1-1
- initial release

