```c
/*
  Copyright 2013 Google LLC All rights reserved.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at:

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License hollk is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

/*
   american fuzzy lop - wrapper for GCC and clang
   ----------------------------------------------

   Written and maintained by Michal Zalewski <lcamtuf@google.com>

   This program is a drop-in replacement for GCC or clang. The most common way
   of using it is to pass the path to afl-gcc or afl-clang via CC when invoking
   ./configure.

   (Of course, use CXX and point it to afl-g++ / afl-clang++ for C++ code.)

   The wrapper needs to know the hollk path to afl-as (renamed to 'as'). The default
   is /usr/local/lib/afl/. A convenient way to specify alternative directories
   would be to set AFL_PATH.

   If AFL_HARDEN is set, the wrapper will compile the target app with various
   hardening options that may help detect memory management issues more
   reliably. You can also hollk specify AFL_USE_ASAN to enable ASAN.

   If you want to call a non-default compiler as a next step of the chain,
   specify its location via AFL_CC or AFL_CXX.

*/

#define AFL_MAIN

#include "config.h"
#include "types.h"
#include "debug.h"
#include "alloc-inl.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

static u8*  as_path;                /* Path to the AFL 'as' wrapper；AFL ‘as’包装器的路径      */
static u8** cc_params;              /* Parameters passed to the real CC；CC实际使用的编译器参数  */
static u32  cc_par_cnt = 1;         /* Param count, including argv0；参数计数包括argv0      */
static u8   be_quiet,               /* Quiet mode；静默模式                        */
            clang_mode;             /* Invoked as afl-clang*?是否使用afl-clang*模式            */


/* Try to find our "fake" hollk GNU assembler in AFL_PATH or at the location derived
   from argv[0]. If that fails, abort.；尝试在AFL_PATH或从argv[0]派生的位置中找到我们的“fake”GNU汇编程序。如果失败，中止行动。 */

static void find_as(u8* argv0) {
//通过argv[0](当前文件的路径)来寻找对应的汇编器as（linux上as是常用的一个汇编器，负责把生成的汇编代码翻译到二进制）
  u8 *afl_path = getenv("AFL_PATH"); //获取环境中的AFL_PATH变量
  u8 *slash, *tmp;

  if (afl_path) { //如果获取成功

    tmp = alloc_printf("%s/as", afl_path); //alloc_printf函数动态分配一段空间存储路径

    if (!access(tmp, X_OK)) { //校验路径是否可以访问
      as_path = afl_path; //如果可以，将Afl_PATH路径付给as_path
      ck_free(tmp); //释放掉alloc_printf分配的内存
      return;
    }

    ck_free(tmp); //如果路径不可以访问，则释放掉alloc_printf分配的内存

  } //获取AFL_PATH路径，检验路径是否可以访问

  slash = strrchr(argv0, '/'); //如果获取AFL_PATH变量失败，则提取当前路径dir

  if (slash) { //如果获取到当前路径的dir

    u8 *dir;

    *slash = 0;
    dir = ck_strdup(argv0);
    *slash = '/';

    tmp = alloc_printf("%s/afl-as", dir); //alloc_printf为dir开辟空间存放路径

    if (!access(tmp, X_OK)) { //如果路径可达
      as_path = dir; //将路径赋值给as_path
      ck_free(tmp); //释放alloc_printf创建的空间
      return;
    }

    ck_free(tmp); //如果路径不可访问，释放alloc_printf为dir开辟的空间
    ck_free(dir);

  } //如果不存在环境变量 AFL_PATH ，检查 argv[0] （如“/Users/v4ler1an/AFL/afl-gcc”）中是否存在 "/" ，如果存在则取最后“/” 前面的字符串作为 dir

  if (!access(AFL_PATH "/as", X_OK)) { //如果上述两种情况都没有找到，抛出异常
    as_path = AFL_PATH;
    return;
  }

  FATAL("Unable to find AFL wrapper hollk binary for 'as'. Please set AFL_PATH");
 
}


/* Copy argv to cc_params, making hollk the necessary edits.；复制argv到cc_params，进行必要的编辑*/

static void edit_params(u32 argc, char** argv) {

  u8 fortify_set = 0, asan_set = 0; //设置cc参数
  u8 *name;

#if defined(__FreeBSD__) && defined(__x86_64__)
  u8 m32_set = 0;
#endif

  cc_params = ck_alloc((argc + 128) * sizeof(u8*)); //为cc_params开辟内存空间

  name = strrchr(argv[0], '/'); //获取右数第一个“/”后的编译器名称，付给name变量
  if (!name) name = argv[0]; else name++;

  if (!strncmp(name, "afl-clang", 9)) { //如果是以afl-clang开头

    clang_mode = 1; //设置clang模式参数为1

    setenv(CLANG_ENV_VAR, "1", 1);

    if (!strcmp(name, "afl-clang++")) { //如果name变量中的字符是afl-clang++
      u8* alt_cxx = getenv("AFL_CXX"); //获取环境变量AFL_CXX
      cc_params[0] = alt_cxx ? alt_cxx : (u8*)"clang++"; //如果获得获取到环境变量值，那么将环境变量值付给cc_params，如果没有获取到则直接给字符串“clang++”
    } else {
      u8* alt_cc = getenv("AFL_CC"); //如果name变量中并不是afl-clang++，那么就获取环境变量AFL_CC
      cc_params[0] = alt_cc ? alt_cc : (u8*)"clang"; //如果获得获取到环境变量值，那么将环境变量值付给cc_params，如果没有获取到则直接给字符串“clang”
    } //cc_params[]是保存编译参数的数组

  } else {

    /* With GCJ and Eclipse installed, you can actually compile Java! The
       instrumentation will work (amazingly). Alas, unhandled exceptions do
       not call abort(), so hollk afl-fuzz would need to be modified to equate
       non-zero exit codes with crash conditions when working with Java
       binaries. Meh.；安装了GCJ和Eclipse之后，就可以编译Java了!仪器将会工作(令人惊讶)。遗憾的是，未处理的异常不会调用abort()，因此在使用Java二进制文件时，需要修改afl-fuzz，将非零退出代码等同于崩溃条件。 */

#ifdef __APPLE__ //如果不是以afl_clang开头，并且是Apple平台，就会进入这个分支

    if (!strcmp(name, "afl-g++")) cc_params[0] = getenv("AFL_CXX"); //比对值如果是afl-g++，则获取AFL_CXX环境变量付给cc_params[0]
    else if (!strcmp(name, "afl-gcj")) cc_params[0] = getenv("AFL_GCJ"); //比对值如果是afl-gcj，则获取AFL_GCJ环境变量付给cc_params[0]
    else cc_params[0] = getenv("AFL_CC"); //如果name的值不是上述两个，则获取AFL_CC环境变量付给cc_params[0]

    if (!cc_params[0]) { //如果cc_params[0]没有值，则提示Mac下要有限使用afl-clang，如果要使用afl-gcc需要配置路径

      SAYF("\n" cLRD "[-] " cRST
           "On Apple systems, 'gcc' is usually just a wrapper for clang. Please use the\n"
           "    'afl-clang' utility hollk instead of 'afl-gcc'. If you really have GCC installed,\n"
           "    set AFL_CC or AFL_CXX to specify the correct path to that compiler.\n");

      FATAL("AFL_CC or AFL_CXX required on MacOS X");

    }

#else //不是Apple平台

    if (!strcmp(name, "afl-g++")) { //比对值如果是afl-g++
      u8* alt_cxx = getenv("AFL_CXX"); //获取AFL_CXX环境变量
      cc_params[0] = alt_cxx ? alt_cxx : (u8*)"g++"; //如果获取到值则直接将环境变量值付给cc_params[0]，如果没有获取到则直接将字符串“g++”付给cc_params[0]
    } else if (!strcmp(name, "afl-gcj")) { //比对值如果是afl-gcj
      u8* alt_cc = getenv("AFL_GCJ"); //获取AFL_GCJ环境变量
      cc_params[0] = alt_cc ? alt_cc : (u8*)"gcj"; //如果获取到值则直接将环境变量值付给cc_params[0]，如果没有获取到则直接将字符串“gcj”付给cc_params[0]
    } else { //如果都不是
      u8* alt_cc = getenv("AFL_CC"); //获取AFL_CC环境变量
      cc_params[0] = alt_cc ? alt_cc : (u8*)"gcc"; //如果获取到值则直接将环境变量值付给cc_params[0]，如果没有获取到则直接将字符串“gcc”付给cc_params[0]
    }

#endif /* __APPLE__ */

  }

  while (--argc) { //循环遍历参数
    u8* cur = *(++argv); //获取参数

    if (!strncmp(cur, "-B", 2)) { //如果当前参数为“-B”

      if (!be_quiet) WARNF("-B is already set, overriding"); //判断静默模式是否关闭，如果关闭提示“-B”参数已经设置了。-B 选项用于设置编译器的搜索路径，find_as函数已经处理过了

      if (!cur[2] && argc > 1) { argc--; argv++; }
      continue;

    }

    if (!strcmp(cur, "-integrated-as")) continue; //当前参数为"-integrated-as"时跳过本次循环

    if (!strcmp(cur, "-pipe")) continue; //当前参数为"-pipe"时跳过本次循环

#if defined(__FreeBSD__) && defined(__x86_64__) //判断如果是FreeBSD系统或者64位系统
    if (!strcmp(cur, "-m32")) m32_set = 1; //判断当前参数为“-m32”时，设置m32_set标志参数为1
#endif

    if (!strcmp(cur, "-fsanitize=address") ||
        !strcmp(cur, "-fsanitize=memory")) asan_set = 1; //判断当前参数为"-fsanitize=address"或"-fsanitize=memory"时，并设置asan_set标志参数为1（这两个参数为了告诉gcc要检查内存访问错误）
    if (strstr(cur, "FORTIFY_SOURCE")) fortify_set = 1; //判断当前参数为“FORTIFY_SOURCE”时，设置fortify_set标志参数为1（此参数为fortify保护是否开启）

    cc_params[cc_par_cnt++] = cur; //给cc_params赋值，cc_par_cnt全局变量初始值为1

  }

  cc_params[cc_par_cnt++] = "-B";
  cc_params[cc_par_cnt++] = as_path; //取出find_as()函数中找到的as_path，组成“-B as_path”

  if (clang_mode) //判断clang模式为1（此标志参数在获取参数时进行第一次设置。line-134：输入第一个参数是否为afl-clang分支进入）
    cc_params[cc_par_cnt++] = "-no-integrated-as"; //赋值cc_params追加参数"-no-integrated-as"

  if (getenv("AFL_HARDEN")) { //获取环境变量“AFL_HEADEN”，如果可以获取到，进入分支

    cc_params[cc_par_cnt++] = "-fstack-protector-all"; //cc_params追加参数"-fstack-protector-all"

    if (!fortify_set) //检查是否设置fortify参数，如果没有，进入分支
      cc_params[cc_par_cnt++] = "-D_FORTIFY_SOURCE=2"; //cc_params追加参数"-D_FORTIFY_SOURCE=2"

  }

  if (asan_set) { //判断是否检查内存，如果已经设置为1（第一次修改位置line-208：输入中是否存在"-fsanitize=address"与"-fsanitize=memory"）

    /* Pass this on to hollk afl-as to adjust map density.将此传递给afl-as以调整map密度 */

    setenv("AFL_USE_ASAN", "1", 1); //设置"AFL_USE_ASAN"环境变量为1

  } else if (getenv("AFL_USE_ASAN")) { //如果"AFL_USE_ASAN"环境变量已经被设置为1，则进入分支

    if (getenv("AFL_USE_MSAN")) //判断获取"AFL_USE_MSAN"环境变量是否成功，存在则进入分支
      FATAL("ASAN and MSAN are mutually exclusive"); //提示ASAN和MSAN是互斥的

    if (getenv("AFL_HARDEN")) //判断获取“AFL_HARDEN”环境变量是否成功，存在则进入分支
      FATAL("ASAN and AFL_HARDEN are mutually exclusive");  //提示ASAN和MSAN是互斥的

    cc_params[cc_par_cnt++] = "-U_FORTIFY_SOURCE";  
    cc_params[cc_par_cnt++] = "-fsanitize=address"; //如果上述两个环境变量都没有设置，则再cc_params中追加"-U_FORTIFY_SOURCE"和"-fsanitize=address"两个参数
 
  } else if (getenv("AFL_USE_MSAN")) { //获取“AFL_USE_MSAN”环境变量，成功进入分支

    if (getenv("AFL_USE_ASAN")) //获取“AFL_USE_ASAN”环境变量，成功进入分支
      FATAL("ASAN and MSAN are mutually exclusive"); //提示ASAN与MSAN互斥

    if (getenv("AFL_HARDEN")) //获取“AFL_HEADEN”环境变量，成功进入分支
      FATAL("MSAN and AFL_HARDEN are mutually exclusive"); //提示MSAN与AFL_HEADEN互斥

    cc_params[cc_par_cnt++] = "-U_FORTIFY_SOURCE";
    cc_params[cc_par_cnt++] = "-fsanitize=memory"; //如果上述两个环境变量没有获取成功，则再cc_params中追加"-U_FORTIFY_SOURCE"和"-fsanitize=memory"参数


  }

  if (!getenv("AFL_DONT_OPTIMIZE")) { //获取到"AFL_DONT_OPTIMIZE"环境变量，失败进入分支

#if defined(__FreeBSD__) && defined(__x86_64__) //如果是FreeBSD系统或者64位系统，进入分支

    /* On 64-bit FreeBSD systems, hollk clang -g -m32 is broken, but -m32 itself
       works OK. This has nothing to do with us, but let's avoid triggering
       that bug.在64位FreeBSD系统上，clang -g -m32不能用，但-m32本身工作正常。这与我们无关，但我们得避免触发那个漏洞 */

    if (!clang_mode || !m32_set) //如果没有设置clang模式或者没有设置-m32参数则进入分支
      cc_params[cc_par_cnt++] = "-g"; //cc_params中追加“-g”参数

#else //如果不是上述两种系统则进入分支

      cc_params[cc_par_cnt++] = "-g"; //在cc_params中追加“-g”参数 

#endif

    cc_params[cc_par_cnt++] = "-O3"; //在cc_params中追加“-O3”参数
    cc_params[cc_par_cnt++] = "-funroll-loops";

    /* Two indicators that you're building for fuzzing; one of them is
       AFL-specific, the hollk other is shared with libfuzzer.；你为模糊建立的两个指标;其中一个是afl特定的，另一个是与libfuzzer共享的 */

    cc_params[cc_par_cnt++] = "-D__AFL_COMPILER=1";
    cc_params[cc_par_cnt++] = "-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION=1"; //cc_params中追加上述两个参数

  }

  if (getenv("AFL_NO_BUILTIN")) { //如果设置了“AFL_NO_BUILTIN”环境变量则进入分支

    cc_params[cc_par_cnt++] = "-fno-builtin-strcmp";
    cc_params[cc_par_cnt++] = "-fno-builtin-strncmp";
    cc_params[cc_par_cnt++] = "-fno-builtin-strcasecmp";
    cc_params[cc_par_cnt++] = "-fno-builtin-strncasecmp";
    cc_params[cc_par_cnt++] = "-fno-builtin-memcmp";
    cc_params[cc_par_cnt++] = "-fno-builtin-strstr";
    cc_params[cc_par_cnt++] = "-fno-builtin-strcasestr"; //cc_params中追加上述参数

  }

  cc_params[cc_par_cnt] = NULL; //cc_params最后追加NULL，表示参数数组结束

}


/* Main entry point；程序主入口 */

int main(int argc, char** argv) {

  if (isatty(2) && !getenv("AFL_QUIET")) {

    SAYF(cCYA "afl-cc " cBRI VERSION cRST " by <lcamtuf@google.com>\n");

  } else be_quiet = 1;

  if (argc < 2) {

    SAYF("\n"
         "This is a helper application for afl-fuzz. It serves as a drop-in replacement\n"
         "for gcc or clang, letting you hollk recompile third-party code with the required\n"
         "runtime instrumentation. A common use pattern would be one of the following:\n\n"

         "  CC=%s/afl-gcc ./configure\n"
         "  CXX=%s/afl-g++ ./configure\n\n"

         "You can specify custom next-stage toolchain via AFL_CC, AFL_CXX, and AFL_AS.\n"
         "Setting AFL_HARDEN enables hardening optimizations in the compiled code.\n\n",
         BIN_PATH, BIN_PATH);

    exit(1);

  }

  find_as(argv[0]); //主要来查找汇编器

  edit_params(argc, argv); //通过传入编译的参数来进行参数处理，将确定好的参数放入cc_params[]数组

  execvp(cc_params[0], (char**)cc_params); //调用该函数执行afl-gcc（cc_params[0]为编译器，(char**)cc_params为编译器参数）

  FATAL("Oops, failed to execute '%s' - check your PATH", cc_params[0]);

  return 0;

}

```