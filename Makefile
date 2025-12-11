# LDAP BOF Collection Makefile
CC = x86_64-w64-mingw32-gcc
STRIP = x86_64-w64-mingw32-strip
CFLAGS = -I _include -Os -masm=intel -fno-stack-protector -mno-stack-arg-probe -DBOF

all: bof

bof: clean
	@mkdir -p _bin/LDAP && echo '[*] Creating _bin/LDAP/ directory'
	@echo '[*] Building GET commands...'
	@$(CC) $(CFLAGS) -c src/get/get-users.c -o _bin/LDAP/get-users.x64.o && $(STRIP) --strip-unneeded _bin/LDAP/get-users.x64.o && echo '[+] get-users'
	@$(CC) $(CFLAGS) -c src/get/get-computers.c -o _bin/LDAP/get-computers.x64.o && $(STRIP) --strip-unneeded _bin/LDAP/get-computers.x64.o && echo '[+] get-computers'
	@$(CC) $(CFLAGS) -c src/get/get-groups.c -o _bin/LDAP/get-groups.x64.o && $(STRIP) --strip-unneeded _bin/LDAP/get-groups.x64.o && echo '[+] get-groups'
	@$(CC) $(CFLAGS) -c src/get/get-usergroups.c -o _bin/LDAP/get-usergroups.x64.o && $(STRIP) --strip-unneeded _bin/LDAP/get-usergroups.x64.o && echo '[+] get-usergroups'
	@$(CC) $(CFLAGS) -c src/get/get-groupmembers.c -o _bin/LDAP/get-groupmembers.x64.o && $(STRIP) --strip-unneeded _bin/LDAP/get-groupmembers.x64.o && echo '[+] get-groupmembers'
	@$(CC) $(CFLAGS) -c src/get/get-object.c -o _bin/LDAP/get-object.x64.o && $(STRIP) --strip-unneeded _bin/LDAP/get-object.x64.o && echo '[+] get-object'
	@$(CC) $(CFLAGS) -c src/get/get-domaininfo.c -o _bin/LDAP/get-domaininfo.x64.o && $(STRIP) --strip-unneeded _bin/LDAP/get-domaininfo.x64.o && echo '[+] get-domaininfo'
	@$(CC) $(CFLAGS) -c src/get/get-maq.c -o _bin/LDAP/get-maq.x64.o && $(STRIP) --strip-unneeded _bin/LDAP/get-maq.x64.o && echo '[+] get-maq'
	@$(CC) $(CFLAGS) -c src/get/get-writable.c -o _bin/LDAP/get-writable.x64.o && $(STRIP) --strip-unneeded _bin/LDAP/get-writable.x64.o && echo '[+] get-writable'
	@$(CC) $(CFLAGS) -c src/get/get-delegation.c -o _bin/LDAP/get-delegation.x64.o && $(STRIP) --strip-unneeded _bin/LDAP/get-delegation.x64.o && echo '[+] get-delegation'
	@$(CC) $(CFLAGS) -c src/get/get-uac.c -o _bin/LDAP/get-uac.x64.o && $(STRIP) --strip-unneeded _bin/LDAP/get-uac.x64.o && echo '[+] get-uac'
	@$(CC) $(CFLAGS) -c src/get/get-attribute.c -o _bin/LDAP/get-attribute.x64.o && $(STRIP) --strip-unneeded _bin/LDAP/get-attribute.x64.o && echo '[+] get-attribute'
	@$(CC) $(CFLAGS) -c src/get/get-spn.c -o _bin/LDAP/get-spn.x64.o && $(STRIP) --strip-unneeded _bin/LDAP/get-spn.x64.o && echo '[+] get-spn'
	@$(CC) $(CFLAGS) -c src/get/get-acl.c -o _bin/LDAP/get-acl.x64.o && $(STRIP) --strip-unneeded _bin/LDAP/get-acl.x64.o && echo '[+] get-acl'
	@$(CC) $(CFLAGS) -c src/get/get-rbcd.c -o _bin/LDAP/get-rbcd.x64.o && $(STRIP) --strip-unneeded _bin/LDAP/get-rbcd.x64.o && echo '[+] get-rbcd'
	@echo '[*] Building ADD commands...'
	@$(CC) $(CFLAGS) -c src/add/add-user.c -o _bin/LDAP/add-user.x64.o && $(STRIP) --strip-unneeded _bin/LDAP/add-user.x64.o && echo '[+] add-user'
	@$(CC) $(CFLAGS) -c src/add/add-computer.c -o _bin/LDAP/add-computer.x64.o && $(STRIP) --strip-unneeded _bin/LDAP/add-computer.x64.o && echo '[+] add-computer'
	@$(CC) $(CFLAGS) -c src/add/add-group.c -o _bin/LDAP/add-group.x64.o && $(STRIP) --strip-unneeded _bin/LDAP/add-group.x64.o && echo '[+] add-group'
	@$(CC) $(CFLAGS) -c src/add/add-groupmember.c -o _bin/LDAP/add-groupmember.x64.o && $(STRIP) --strip-unneeded _bin/LDAP/add-groupmember.x64.o && echo '[+] add-groupmember'
	@$(CC) $(CFLAGS) -c src/add/add-ou.c -o _bin/LDAP/add-ou.x64.o && $(STRIP) --strip-unneeded _bin/LDAP/add-ou.x64.o && echo '[+] add-ou'
	@$(CC) $(CFLAGS) -c src/add/add-sidhistory.c -o _bin/LDAP/add-sidhistory.x64.o && $(STRIP) --strip-unneeded _bin/LDAP/add-sidhistory.x64.o && echo '[+] add-sidhistory'
	@$(CC) $(CFLAGS) -c src/add/add-spn.c -o _bin/LDAP/add-spn.x64.o && $(STRIP) --strip-unneeded _bin/LDAP/add-spn.x64.o && echo '[+] add-spn'
	@$(CC) $(CFLAGS) -c src/add/add-attribute.c -o _bin/LDAP/add-attribute.x64.o && $(STRIP) --strip-unneeded _bin/LDAP/add-attribute.x64.o && echo '[+] add-attribute'
	@$(CC) $(CFLAGS) -c src/add/add-uac.c -o _bin/LDAP/add-uac.x64.o && $(STRIP) --strip-unneeded _bin/LDAP/add-uac.x64.o && echo '[+] add-uac'
	@$(CC) $(CFLAGS) -c src/add/add-delegation.c -o _bin/LDAP/add-delegation.x64.o && $(STRIP) --strip-unneeded _bin/LDAP/add-delegation.x64.o && echo '[+] add-delegation'
	@$(CC) $(CFLAGS) -c src/add/add-rbcd.c -o _bin/LDAP/add-rbcd.x64.o && $(STRIP) --strip-unneeded _bin/LDAP/add-rbcd.x64.o && echo '[+] add-rbcd'
	@$(CC) $(CFLAGS) -c src/add/add-ace.c -o _bin/LDAP/add-ace.x64.o && $(STRIP) --strip-unneeded _bin/LDAP/add-ace.x64.o && echo '[+] add-ace'
	@echo '[*] Building SET commands...'
	@$(CC) $(CFLAGS) -c src/set/set-password.c -o _bin/LDAP/set-password.x64.o && $(STRIP) --strip-unneeded _bin/LDAP/set-password.x64.o && echo '[+] set-password'
	@$(CC) $(CFLAGS) -c src/set/set-spn.c -o _bin/LDAP/set-spn.x64.o && $(STRIP) --strip-unneeded _bin/LDAP/set-spn.x64.o && echo '[+] set-spn'
	@$(CC) $(CFLAGS) -c src/set/set-delegation.c -o _bin/LDAP/set-delegation.x64.o && $(STRIP) --strip-unneeded _bin/LDAP/set-delegation.x64.o && echo '[+] set-delegation'
	@$(CC) $(CFLAGS) -c src/set/set-attribute.c -o _bin/LDAP/set-attribute.x64.o && $(STRIP) --strip-unneeded _bin/LDAP/set-attribute.x64.o && echo '[+] set-attribute'
	@$(CC) $(CFLAGS) -c src/set/set-uac.c -o _bin/LDAP/set-uac.x64.o && $(STRIP) --strip-unneeded _bin/LDAP/set-uac.x64.o && echo '[+] set-uac'
	@$(CC) $(CFLAGS) -c src/set/set-owner.c -o _bin/LDAP/set-owner.x64.o && $(STRIP) --strip-unneeded _bin/LDAP/set-owner.x64.o && echo '[+] set-owner'
	@echo '[*] Building MOVE commands...'
	@$(CC) $(CFLAGS) -c src/move/move-object.c -o _bin/LDAP/move-object.x64.o && $(STRIP) --strip-unneeded _bin/LDAP/move-object.x64.o && echo '[+] move-object'
	@echo '[*] Building REMOVE commands...'
	@$(CC) $(CFLAGS) -c src/remove/remove-groupmember.c -o _bin/LDAP/remove-groupmember.x64.o && $(STRIP) --strip-unneeded _bin/LDAP/remove-groupmember.x64.o && echo '[+] remove-groupmember'
	@$(CC) $(CFLAGS) -c src/remove/remove-object.c -o _bin/LDAP/remove-object.x64.o && $(STRIP) --strip-unneeded _bin/LDAP/remove-object.x64.o && echo '[+] remove-object'
	@$(CC) $(CFLAGS) -c src/remove/remove-delegation.c -o _bin/LDAP/remove-delegation.x64.o && $(STRIP) --strip-unneeded _bin/LDAP/remove-delegation.x64.o && echo '[+] remove-delegation'
	@$(CC) $(CFLAGS) -c src/remove/remove-spn.c -o _bin/LDAP/remove-spn.x64.o && $(STRIP) --strip-unneeded _bin/LDAP/remove-spn.x64.o && echo '[+] remove-spn'
	@$(CC) $(CFLAGS) -c src/remove/remove-attribute.c -o _bin/LDAP/remove-attribute.x64.o && $(STRIP) --strip-unneeded _bin/LDAP/remove-attribute.x64.o && echo '[+] remove-attribute'
	@$(CC) $(CFLAGS) -c src/remove/remove-rbcd.c -o _bin/LDAP/remove-rbcd.x64.o && $(STRIP) --strip-unneeded _bin/LDAP/remove-rbcd.x64.o && echo '[+] remove-rbcd'
	@$(CC) $(CFLAGS) -c src/remove/remove-ace.c -o _bin/LDAP/remove-ace.x64.o && $(STRIP) --strip-unneeded _bin/LDAP/remove-ace.x64.o && echo '[+] remove-ace'
	@$(CC) $(CFLAGS) -c src/remove/remove-uac.c -o _bin/LDAP/remove-uac.x64.o && $(STRIP) --strip-unneeded _bin/LDAP/remove-uac.x64.o && echo '[+] remove-uac'

	@echo '[*] Build complete!'

clean:
	@rm -rf _bin/LDAP
