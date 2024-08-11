DC?=ldmd2
DEBUG?=0

BINDIR=bin
SRCDIR=src
OBJDIR=obj
DOCDIR=doc
DEBUGFLAGS=

ifeq ($(DEBUG), 1)
	ifeq ($(findstring gdc, $(DC)), gdc)
		DEBUGFLAGS=-g -fdebug=db -fdebug=msg -fdebug=user
	else
		DEBUGFLAGS=-g -debug=db -debug=msg -debug=user
	endif
endif

SOULFINDFILES=client.d \
         db.d \
         message_codes.d \
         messages.d \
         pm.d \
         room.d \
         server.d \
         defines.d \
         sqlite3_imp.d
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
ifeq ($(findstring gdc, $(DC)), gdc)
	$(DC) $(SOULFINDFILES) -I$(SRCDIR) -o$(SOULFIND) -lsqlite3 $(DEBUGFLAGS)
else
	$(DC) $(SOULFINDFILES) -I$(SRCDIR) -od$(OBJDIR) -of$(SOULFIND) -L-lsqlite3 $(DEBUGFLAGS)
endif

$(SOULSETUP): $(SOULSETUPFILES)
	@mkdir -p $(OBJDIR)
	@mkdir -p $(BINDIR)
ifeq ($(findstring gdc, $(DC)), gdc)
		$(DC) $(SOULSETUPFILES) -I$(SRCDIR) -o$(SOULSETUP) -lsqlite3 $(DEBUGFLAGS)
else
		$(DC) $(SOULSETUPFILES) -I$(SRCDIR) -od$(OBJDIR) -of$(SOULSETUP) -L-lsqlite3 $(DEBUGFLAGS)
endif

clean:
	-rm -rf $(OBJDIR)
	-rm -rf $(BINDIR)
