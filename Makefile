DC?=ldmd2 -g

DEBUG?=none

BINDIR=bin
SRCDIR=src
OBJDIR=obj
DOCDIR=doc

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
         undead/stream.d \
         undead/utf.d
SOULFINDFILES:=$(addprefix $(SRCDIR)/,$(SOULFINDFILES))


SOULSETUPFILES=soulsetup.d \
               defines.d \
               db.d \
               undead/doformat.d \
               undead/internal/file.d \
               undead/cstream.d \
               undead/socketstream.d \
               undead/stream.d \
               undead/utf.d
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
		$(DC) $(SOULFINDFILES) -I$(SRCDIR) -o$(SOULFIND) -lsqlite3 -fdebug=$(DEBUG)
else
		$(DC) $(SOULFINDFILES) -I$(SRCDIR) -od$(OBJDIR) -of$(SOULFIND) -L-lsqlite3 -debug=$(DEBUG)
endif

$(SOULSETUP): $(SOULSETUPFILES)
	@mkdir -p $(OBJDIR)
	@mkdir -p $(BINDIR)
ifeq ($(findstring gdc, $(DC)), gdc)
		$(DC) $(SOULSETUPFILES) -I$(SRCDIR) -o$(SOULSETUP) -lsqlite3 -fdebug=$(DEBUG)
else
		$(DC) $(SOULSETUPFILES) -I$(SRCDIR) -od$(OBJDIR) -of$(SOULSETUP) -L-lsqlite3 -debug=$(DEBUG)
endif

clean:
	-rm -rf $(OBJDIR)
	-rm -rf $(BINDIR)
