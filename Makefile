DC?=dmd -g

DEBUG?=1

BINDIR=bin
SRCDIR=src
OBJDIR=obj
DOCDIR=doc

PREFIX=/usr

SOULFINDFILES=client.d \
         db.d \
         message_codes.d \
         messages.d \
         pm.d \
         room.d \
         server.d \
         defines.d \
         sqlite3_imp.d \
         undead/doformat.d \
         undead/internal/file.d \
         undead/cstream.d \
         undead/socketstream.d \
         undead/stream.d
SOULFINDFILES:=$(addprefix $(SRCDIR)/,$(SOULFINDFILES))


SOULSETUPFILES=soulsetup.d \
               defines.d \
               db.d \
               undead/doformat.d \
               undead/internal/file.d \
               undead/cstream.d \
               undead/socketstream.d \
               undead/stream.d
SOULSETUPFILES:=$(addprefix $(SRCDIR)/,$(SOULSETUPFILES))


SOULFIND=$(BINDIR)/soulfind
SOULSETUP=$(BINDIR)/soulsetup

all: soulfind soulsetup

soulfind: $(SOULFIND)

soulsetup: $(SOULSETUP)

$(SOULFIND): $(SOULFINDFILES)
	@mkdir -p $(OBJDIR)
	@mkdir -p $(BINDIR)
ifeq ($(findstring gdc, $(DC)), gdc)
		$(DC) $(SOULFINDFILES) -I$(SRCDIR) -o$(SOULFIND) -lsqlite3 -fversion=Soulfind -fdebug=$(DEBUG)
else
		$(DC) $(SOULFINDFILES) -I$(SRCDIR) -od$(OBJDIR) -of$(SOULFIND) -L-lsqlite3 -version=Soulfind -debug=$(DEBUG)
endif

$(SOULSETUP): $(SOULSETUPFILES)
	@mkdir -p $(OBJDIR)
	@mkdir -p $(BINDIR)
ifeq ($(findstring gdc, $(DC)), gdc)
		$(DC) $(SOULSETUPFILES) -I$(SRCDIR) -o$(SOULSETUP) -lsqlite3 -fversion=Soulsetup -fdebug=$(DEBUG)
else
		$(DC) $(SOULSETUPFILES) -I$(SRCDIR) -od$(OBJDIR) -of$(SOULSETUP) -L-lsqlite3 -version=Soulsetup -debug=$(DEBUG)
endif

install: install_soulfind install_soulsetup install_doc

install_soulfind: $(SOULFIND)
	install -D --strip $(SOULFIND)  $(PREFIX)/$(SOULFIND)

install_soulsetup: $(SOULSETUP)
	install -D --strip $(SOULSETUP) $(PREFIX)/$(SOULSETUP)

clean:
	-rm -rf $(OBJDIR)
	-rm -rf $(BINDIR)

clean_doc:
	-rm -f $(DOCDIR)/soulfind.1
	-rm -f $(DOCDIR)/soulsetup.1

documentation: $(DOCDIR)/soulfind.1 $(DOCDIR)/soulsetup.1

$(DOCDIR)/soulfind.1 $(DOCDIR)/soulsetup.1:
	cd $(DOCDIR) ; docbook2manxml.pl `basename $@ .1`.xml | man_xml.pl

install_doc: $(DOCDIR)/soulfind.1 $(DOCDIR)/soulsetup.1
	install --mode=644 -D $(DOCDIR)/soulfind.1  $(PREFIX)/share/man/man1/soulfind.1
	install --mode=644 -D $(DOCDIR)/soulsetup.1 $(PREFIX)/share/man/man1/soulsetup.1
