DC?=ldmd2
DEBUG?=0

BINDIR=bin
SRCDIR=src
OBJDIR=obj
DOCDIR=doc
DEBUGFLAGS=

ifeq ($(DEBUG), 1)
	DEBUGFLAGS=-g -debug=db -debug=msg -debug=user
endif

SOULFINDFILES=client.d \
         db.d \
         message_codes.d \
         messages.d \
         pm.d \
         room.d \
         server.d \
         defines.d
SOULFINDFILES:=$(addprefix $(SRCDIR)/,$(SOULFINDFILES))


SOULSETUPFILES=soulsetup.d \
               defines.d \
               db.d
SOULSETUPFILES:=$(addprefix $(SRCDIR)/,$(SOULSETUPFILES))


SOULFIND=$(BINDIR)/soulfind
SOULSETUP=$(BINDIR)/soulsetup

all: soulfind soulsetup

soulfind: $(SOULFIND)

soulsetup: $(SOULSETUP)

$(SOULFIND): $(SOULFINDFILES)
	@mkdir -p $(OBJDIR)
	@mkdir -p $(BINDIR)
	$(DC) $(SOULFINDFILES) -I$(SRCDIR) -od$(OBJDIR) -of$(SOULFIND) -L-lsqlite3 $(DEBUGFLAGS)

$(SOULSETUP): $(SOULSETUPFILES)
	@mkdir -p $(OBJDIR)
	@mkdir -p $(BINDIR)
	$(DC) $(SOULSETUPFILES) -I$(SRCDIR) -od$(OBJDIR) -of$(SOULSETUP) -L-lsqlite3 $(DEBUGFLAGS)

clean:
	-rm -rf $(OBJDIR)
	-rm -rf $(BINDIR)
