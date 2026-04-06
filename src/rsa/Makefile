<<<<<<< HEAD
ARTIFACT = rsa2
=======
ARTIFACT = rsa
>>>>>>> ec965374089f5d8537f09e51ac527072e3336684

#Build architecture/variant string, possible values: x86, armv7le, etc...
PLATFORM ?= x86_64

#Build profile, possible values: release, debug, profile, coverage
BUILD_PROFILE ?= debug

CONFIG_NAME ?= $(PLATFORM)-$(BUILD_PROFILE)
OUTPUT_DIR = build/$(CONFIG_NAME)
TARGET = $(OUTPUT_DIR)/$(ARTIFACT)

#Compiler definitions
<<<<<<< HEAD
=======

>>>>>>> ec965374089f5d8537f09e51ac527072e3336684
CC = qcc -Vgcc_nto$(PLATFORM)
CXX = q++ -Vgcc_nto$(PLATFORM)_cxx
LD = $(CC)

#User defined include/preprocessor flags and libraries
<<<<<<< HEAD
=======

>>>>>>> ec965374089f5d8537f09e51ac527072e3336684
#INCLUDES += -I/path/to/my/lib/include
#INCLUDES += -I../mylib/public

#LIBS += -L/path/to/my/lib/$(PLATFORM)/usr/lib -lmylib
#LIBS += -L../mylib/$(OUTPUT_DIR) -lmylib

#Compiler flags for build profiles
CCFLAGS_release += -O2
CCFLAGS_debug += -g -O0 -fno-builtin
CCFLAGS_coverage += -g -O0 -ftest-coverage -fprofile-arcs
LDFLAGS_coverage += -ftest-coverage -fprofile-arcs
CCFLAGS_profile += -g -O0 -finstrument-functions
LIBS_profile += -lprofilingS

#Generic compiler flags (which include build type flags)
<<<<<<< HEAD
CCFLAGS_all += -Wall -fmessage-length=0
CCFLAGS_all += $(CCFLAGS_$(BUILD_PROFILE))
LDFLAGS_all += $(LDFLAGS_$(BUILD_PROFILE))
LIBS_all += $(LIBS_$(BUILD_PROFILE)) -lcrypto -lssl

DEPS = -Wp,-MMD,$(@:%.o=%.d),-MT,$@

#Macro to expand files recursively: parameters $1 - directory, $2 - extension
rwildcard = $(wildcard $(addprefix $1/*.,$2)) $(foreach d,$(wildcard $1/*),$(call rwildcard,$d,$2))

#Source list
SRCS = $(call rwildcard,src,c)

#Object files list
OBJS = $(addprefix $(OUTPUT_DIR)/,$(addsuffix .o,$(basename $(SRCS))))
=======
CCFLAGS_all += -Wall -fmessage-length=0 
CCFLAGS_all += $(CCFLAGS_$(BUILD_PROFILE))
#Shared library has to be compiled with -fPIC
#CCFLAGS_all += -fPIC
LDFLAGS_all += $(LDFLAGS_$(BUILD_PROFILE)) -lcrypto -lssl
LIBS_all += $(LIBS_$(BUILD_PROFILE))
DEPS = -Wp,-MMD,$(@:%.o=%.d),-MT,$@

#Macro to expand files recursively: parameters $1 -  directory, $2 - extension, i.e. cpp
rwildcard = $(wildcard $(addprefix $1/*.,$2)) $(foreach d,$(wildcard $1/*),$(call rwildcard,$d,$2))

#Source list
SRCS = $(call rwildcard, src, c)

#Object files list
OBJS = $(addprefix $(OUTPUT_DIR)/,$(addsuffix .o, $(basename $(SRCS))))
>>>>>>> ec965374089f5d8537f09e51ac527072e3336684

#Compiling rule
$(OUTPUT_DIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) -c $(DEPS) -o $@ $(INCLUDES) $(CCFLAGS_all) $(CCFLAGS) $<

#Linking rule
<<<<<<< HEAD
$(TARGET): $(OBJS)
	@mkdir -p $(dir $@)
	$(LD) -o $@ $(OBJS) $(LDFLAGS_all) $(LDFLAGS) $(LIBS_all) $(LIBS)
=======
$(TARGET):$(OBJS)
	$(LD) -o $(TARGET) $(LDFLAGS_all) $(LDFLAGS) $(OBJS) $(LIBS_all) $(LIBS)
>>>>>>> ec965374089f5d8537f09e51ac527072e3336684

#Rules section for default compilation and linking
all: $(TARGET)

clean:
	rm -fr $(OUTPUT_DIR)

rebuild: clean all

<<<<<<< HEAD
#Inclusion of dependencies
=======
#Inclusion of dependencies (object files to source and includes)
>>>>>>> ec965374089f5d8537f09e51ac527072e3336684
-include $(OBJS:%.o=%.d)