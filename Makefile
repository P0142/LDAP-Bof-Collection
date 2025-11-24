# LDAP BOF Collection Makefile
CC = x86_64-w64-mingw32-gcc
STRIP = x86_64-w64-mingw32-strip
CFLAGS = -I _include -Os -masm=intel -fno-stack-protector -mno-stack-arg-probe -DBOF

all: bof

bof: clean
	@mkdir -p _bin && echo '[*] Creating _bin directory'
	@echo '[*] Building GET commands...'
	@$(CC) $(CFLAGS) -c src/get/get-users.c -o _bin/get-users.x64.o && $(STRIP) --strip-unneeded _bin/get-users.x64.o && echo '[+] get-users'
	@$(CC) $(CFLAGS) -c src/get/get-computers.c -o _bin/get-computers.x64.o && $(STRIP) --strip-unneeded _bin/get-computers.x64.o && echo '[+] get-computers'
	@$(CC) $(CFLAGS) -c src/get/get-groups.c -o _bin/get-groups.x64.o && $(STRIP) --strip-unneeded _bin/get-groups.x64.o && echo '[+] get-groups'
	@$(CC) $(CFLAGS) -c src/get/get-usergroups.c -o _bin/get-usergroups.x64.o && $(STRIP) --strip-unneeded _bin/get-usergroups.x64.o && echo '[+] get-usergroups'
	@$(CC) $(CFLAGS) -c src/get/get-groupmembers.c -o _bin/get-groupmembers.x64.o && $(STRIP) --strip-unneeded _bin/get-groupmembers.x64.o && echo '[+] get-groupmembers'
	@$(CC) $(CFLAGS) -c src/get/get-object.c -o _bin/get-object.x64.o && $(STRIP) --strip-unneeded _bin/get-object.x64.o && echo '[+] get-object'
	@$(CC) $(CFLAGS) -c src/get/get-domaininfo.c -o _bin/get-domaininfo.x64.o && $(STRIP) --strip-unneeded _bin/get-domaininfo.x64.o && echo '[+] get-domaininfo'
	@$(CC) $(CFLAGS) -c src/get/get-writable.c -o _bin/get-writable.x64.o && $(STRIP) --strip-unneeded _bin/get-writable.x64.o && echo '[+] get-writable'
	@$(CC) $(CFLAGS) -c src/get/get-delegation.c -o _bin/get-delegation.x64.o && $(STRIP) --strip-unneeded _bin/get-delegation.x64.o && echo '[+] get-delegation'
	@$(CC) $(CFLAGS) -c src/get/get-uac.c -o _bin/get-uac.x64.o && $(STRIP) --strip-unneeded _bin/get-uac.x64.o && echo '[+] get-uac'
	@$(CC) $(CFLAGS) -c src/get/get-attribute.c -o _bin/get-attribute.x64.o && $(STRIP) --strip-unneeded _bin/get-attribute.x64.o && echo '[+] get-attribute'
	@$(CC) $(CFLAGS) -c src/get/get-spn.c -o _bin/get-spn.x64.o && $(STRIP) --strip-unneeded _bin/get-spn.x64.o && echo '[+] get-spn'
	@$(CC) $(CFLAGS) -c src/get/get-acl.c -o _bin/get-acl.x64.o && $(STRIP) --strip-unneeded _bin/get-acl.x64.o && echo '[+] get-acl'
	@$(CC) $(CFLAGS) -c src/get/get-rbcd.c -o _bin/get-rbcd.x64.o && $(STRIP) --strip-unneeded _bin/get-rbcd.x64.o && echo '[+] get-rbcd'
	@echo '[*] Building ADD commands...'
	@$(CC) $(CFLAGS) -c src/add/add-user.c -o _bin/add-user.x64.o && $(STRIP) --strip-unneeded _bin/add-user.x64.o && echo '[+] add-user'
	@$(CC) $(CFLAGS) -c src/add/add-computer.c -o _bin/add-computer.x64.o && $(STRIP) --strip-unneeded _bin/add-computer.x64.o && echo '[+] add-computer'
	@$(CC) $(CFLAGS) -c src/add/add-group.c -o _bin/add-group.x64.o && $(STRIP) --strip-unneeded _bin/add-group.x64.o && echo '[+] add-group'
	@$(CC) $(CFLAGS) -c src/add/add-groupmember.c -o _bin/add-groupmember.x64.o && $(STRIP) --strip-unneeded _bin/add-groupmember.x64.o && echo '[+] add-groupmember'
	@$(CC) $(CFLAGS) -c src/add/add-ou.c -o _bin/add-ou.x64.o && $(STRIP) --strip-unneeded _bin/add-ou.x64.o && echo '[+] add-ou'
	@$(CC) $(CFLAGS) -c src/add/add-sidhistory.c -o _bin/add-sidhistory.x64.o && $(STRIP) --strip-unneeded _bin/add-sidhistory.x64.o && echo '[+] add-sidhistory'
	@$(CC) $(CFLAGS) -c src/add/add-spn.c -o _bin/add-spn.x64.o && $(STRIP) --strip-unneeded _bin/add-spn.x64.o && echo '[+] add-spn'
	@$(CC) $(CFLAGS) -c src/add/add-attribute.c -o _bin/add-attribute.x64.o && $(STRIP) --strip-unneeded _bin/add-attribute.x64.o && echo '[+] add-attribute'
	@$(CC) $(CFLAGS) -c src/add/add-uac.c -o _bin/add-uac.x64.o && $(STRIP) --strip-unneeded _bin/add-uac.x64.o && echo '[+] add-uac'
	@$(CC) $(CFLAGS) -c src/add/add-delegation.c -o _bin/add-delegation.x64.o && $(STRIP) --strip-unneeded _bin/add-delegation.x64.o && echo '[+] add-delegation'
	@$(CC) $(CFLAGS) -c src/add/add-rbcd.c -o _bin/add-rbcd.x64.o && $(STRIP) --strip-unneeded _bin/add-rbcd.x64.o && echo '[+] add-rbcd'
	@$(CC) $(CFLAGS) -c src/add/add-ace.c -o _bin/add-ace.x64.o && $(STRIP) --strip-unneeded _bin/add-ace.x64.o && echo '[+] add-ace'
	@echo '[*] Building SET commands...'
	@$(CC) $(CFLAGS) -c src/set/set-password.c -o _bin/set-password.x64.o && $(STRIP) --strip-unneeded _bin/set-password.x64.o && echo '[+] set-password'
	@$(CC) $(CFLAGS) -c src/set/set-spn.c -o _bin/set-spn.x64.o && $(STRIP) --strip-unneeded _bin/set-spn.x64.o && echo '[+] set-spn'
	@$(CC) $(CFLAGS) -c src/set/set-delegation.c -o _bin/set-delegation.x64.o && $(STRIP) --strip-unneeded _bin/set-delegation.x64.o && echo '[+] set-delegation'
	@$(CC) $(CFLAGS) -c src/set/set-attribute.c -o _bin/set-attribute.x64.o && $(STRIP) --strip-unneeded _bin/set-attribute.x64.o && echo '[+] set-attribute'
	@$(CC) $(CFLAGS) -c src/set/set-uac.c -o _bin/set-uac.x64.o && $(STRIP) --strip-unneeded _bin/set-uac.x64.o && echo '[+] set-uac'
	@$(CC) $(CFLAGS) -c src/set/set-owner.c -o _bin/set-owner.x64.o && $(STRIP) --strip-unneeded _bin/set-owner.x64.o && echo '[+] set-owner'
	@echo '[*] Building MOVE commands...'
	@$(CC) $(CFLAGS) -c src/move/move-object.c -o _bin/move-object.x64.o && $(STRIP) --strip-unneeded _bin/move-object.x64.o && echo '[+] move-object'
	@echo '[*] Building REMOVE commands...'
	@$(CC) $(CFLAGS) -c src/remove/remove-groupmember.c -o _bin/remove-groupmember.x64.o && $(STRIP) --strip-unneeded _bin/remove-groupmember.x64.o && echo '[+] remove-groupmember'
	@$(CC) $(CFLAGS) -c src/remove/remove-object.c -o _bin/remove-object.x64.o && $(STRIP) --strip-unneeded _bin/remove-object.x64.o && echo '[+] remove-object'
	@$(CC) $(CFLAGS) -c src/remove/remove-delegation.c -o _bin/remove-delegation.x64.o && $(STRIP) --strip-unneeded _bin/remove-delegation.x64.o && echo '[+] remove-delegation'
	@$(CC) $(CFLAGS) -c src/remove/remove-spn.c -o _bin/remove-spn.x64.o && $(STRIP) --strip-unneeded _bin/remove-spn.x64.o && echo '[+] remove-spn'
	@$(CC) $(CFLAGS) -c src/remove/remove-attribute.c -o _bin/remove-attribute.x64.o && $(STRIP) --strip-unneeded _bin/remove-attribute.x64.o && echo '[+] remove-attribute'
	@$(CC) $(CFLAGS) -c src/remove/remove-rbcd.c -o _bin/remove-rbcd.x64.o && $(STRIP) --strip-unneeded _bin/remove-rbcd.x64.o && echo '[+] remove-rbcd'
	@$(CC) $(CFLAGS) -c src/remove/remove-ace.c -o _bin/remove-ace.x64.o && $(STRIP) --strip-unneeded _bin/remove-ace.x64.o && echo '[+] remove-ace'
	@$(CC) $(CFLAGS) -c src/remove/remove-uac.c -o _bin/remove-uac.x64.o && $(STRIP) --strip-unneeded _bin/remove-uac.x64.o && echo '[+] remove-uac'
	@echo '[*] Build complete!'

clean:
	@rm -rf _bin
