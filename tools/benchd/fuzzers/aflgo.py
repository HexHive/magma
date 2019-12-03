from fuzzer import Fuzzer, FuzzerBenchmark, FuzzerInstance, TargetProgram
import glob
import os
import subprocess
import shutil
from random import randint
import re
import screenutils

SHOW_LINE_NUM_AWK_REGEX = re.compile(r'''(.*?\.(?:[ch]|cpp|cc)):([0-9]*):\+''')

class AFLGoFuzzer(Fuzzer):
    def __init__(self, install_dir):
        super().__init__()

        self.install_dir = install_dir

        self.cc = os.path.join(self.install_dir, "afl-clang-fast")
        self.cxx = os.path.join(self.install_dir, "afl-clang-fast++")
        self.ass = os.path.join(self.install_dir, "afl-as")
        self.fuzz = os.path.join(self.install_dir, "afl-fuzz")

    def gen_targets(self, target_name, out_dir):
        '''
        AFLGo requires a list of file path + line number to direct the fuzzer
        towards.

        We generate this list from the bug patches themselves. This means that
        AFLGo is directed towards finding the bugs that have been
        forward-ported.
        '''
        args = [
            os.path.join(self.install_dir, "showlinenum.awk"),
            "show_header=0",
            "path=1",
        ]
        targets = set()

        # Since we don't know which patch belongs to which target, iterate over
        # all of them and determine by the source code paths whether that
        # particular patch belongs to the given target
        magma_bugs_dir = os.path.join(self.magma_dir, "patches", "bugs")
        patch_glob = glob.glob(os.path.join(magma_bugs_dir, "*.patch"))
        for bug_patch in patch_glob:
            show_line_num_output = None

            with open(bug_patch, 'r') as f:
                result = subprocess.run(args, input=f.read(),
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE,
                                        universal_newlines=True)
                show_line_num_output = result.stdout

            # Generate the source files/line numbers that will go into the
            # targets file
            for line in show_line_num_output.splitlines():
                match = SHOW_LINE_NUM_AWK_REGEX.search(line)
                if not match:
                    continue

                _, src_path = match.group(1).split("codebase/")
                line = int(match.group(2))

                if not src_path.startswith(target_name):
                    continue

                targets.add((src_path, line))

        targets_path = os.path.join(out_dir, 'BBtargets.txt')
        with open(targets_path, 'w') as f:
            for src_path, line in targets:
                f.write('%s:%d\n' % (src_path, line))

        return targets_path

    def compile(self, target_name, output_dir, config=None, **env):
        '''
        Compiles the benchmark and returns a list of TargetProgram objects,
        each object having its `path` data member set to the target's path.
        '''
        args = [
            "/usr/bin/env",
            "make",
            "-j",
            "-C",
            self.magma_dir,
            # "-f %s" % os.path.join(self.magma_dir, "Makefile")
            "clean",
            "all_patches",
            target_name
        ]

        # Setup directory containing all temporary files
        tmp_dir = os.path.join(output_dir, "temp")
        try:
            os.mkdir(tmp_dir)
        except FileExistsError:
            pass
        except:
            raise

        # Generate targets
        targets_path = self.gen_targets(target_name, tmp_dir)

        # Set aflgo-instrumentation flags
        cflags_original = env.get("CFLAGS", "")
        cxxflags_original = env.get("CXXFLAGS", "")

        env["CC"] = self.cc
        env["CXX"] = self.cxx
        env["AS"] = self.ass
        env["CFLAGS"] = "{cflags} -targets={targets_path} -outdir={tmp_dir} -flto -fuse-ld=gold -Wl,-plugin-opt=save-temps".format(
                cflags = cflags_original,
                targets_path = targets_path,
                tmp_dir = tmp_dir
            )
        env["CXXFLAGS"] = "{cxxflags} -targets={targets_path} -outdir={tmp_dir} -flto -fuse-ld=gold -Wl,-plugin-opt=save-temps".format(
                cxxflags = cxxflags_original,
                targets_path = targets_path,
                tmp_dir = tmp_dir
            )

        proc_env = os.environ.copy()
        proc_env.update(env)

        try:
            result = subprocess.run(args, env=proc_env, check=True)
        except subprocess.CalledProcessError as ex:
            print(ex.stderr)
            raise

        # since check=True, reaching this point means compiled successfully
        #
        # Clean up control flow information logged by AFLGo

        uniq_lines = set()
        with open(os.path.join(tmp_dir, "BBnames.txt"), "r") as bbnames:
            for line in bbnames:
                split_line = line.split(":")
                if len(split_line) < 2:
                    continue
                uniq_lines.add("%s:%s\n" % (split_line[0], split_line[1]))

        uniq_lines = sorted(list(uniq_lines))

        with open(os.path.join(tmp_dir, "BBnames.txt"), "w") as bbnames:
            bbnames.writelines(uniq_lines)

        uniq_lines = set()
        with open(os.path.join(tmp_dir, "BBcalls.txt"), "r") as bbcalls:
            for line in bbcalls:
                # Skip empty lines
                if not line.strip():
                    continue
                uniq_lines.add(line)

        uniq_lines = sorted(list(uniq_lines))

        with open(os.path.join(tmp_dir, "BBcalls.txt"), "w") as bbcalls:
            bbcalls.writelines(uniq_lines)

        gen_distance_args = [
            "/usr/bin/env",
            os.path.join(self.install_dir, "scripts", "genDistance.sh"),
            os.path.join(self.magma_dir, "tmp", target_name),
            tmp_dir
        ]

        try:
            result = subprocess.run(gen_distance_args, check=True)
        except subprocess.CalledProcessError as ex:
            print(ex.stderr)
            raise

        # since check=True, reaching this point means compiled successfully
        #
        # Clean and rebuild subject with distance instrumentation
        env["CFLAGS"] = "{cflags} -distance={tmp_dir}/distance.cfg.txt".format(
                cflags = cflags_original,
                tmp_dir = tmp_dir
            )
        env["CXXFLAGS"] = "{cxxflags} -distance={tmp_dir}/distance.cfg.txt".format(
                cxxflags = cxxflags_original,
                tmp_dir = tmp_dir
            )

        proc_env = os.environ.copy()
        proc_env.update(env)

        try:
            result = subprocess.run(args, env=proc_env, check=True)
        except subprocess.CalledProcessError as ex:
            print(ex.stderr)
            raise

        # since check=True, reaching this point means compiled successfully
        targets = []
        for root, _, files in os.walk(os.path.join(self.magma_dir, "build")):
            for f in files:
                cpath = shutil.copy2(os.path.join(root, f), output_dir)
                if os.path.basename(root) == "programs":
                    t = TargetProgram()
                    t["path"] = cpath
                    t["name"] = target_name
                    t["program"] = os.path.basename(t["path"])
                    targets.append(t)

        return targets

    def preprocess(self, **kwargs):
        # os.system("sudo bash -c 'echo core >/proc/sys/kernel/core_pattern'")
        # os.system("sudo bash -c 'cd /sys/devices/system/cpu; echo performance | tee cpu*/cpufreq/scaling_governor'")
        pass

    def launch(self, target, seeds_dir, findings_dir, args=None, timeout=86400, logfile=None):
        fuzz_cmd = "{fuzz} -z exp -c {exploitation_time}s -i {seeds_dir} -o {findings_dir}{args} -- {target_path} {target_args}".format(
                fuzz = self.fuzz,
                exploitation_time = int(0.75 * timeout),
                seeds_dir = seeds_dir,
                findings_dir = findings_dir,
                args = " %s" % args if (args is not None and args != "") else "",
                target_path = target["path"],
                target_args = target["args"]
            )
        cmd = "/usr/bin/env timeout -s INT {timeout}s {fuzz_cmd}".format(
                timeout = timeout,
                fuzz_cmd = fuzz_cmd
            ).split(" ")
        name = "afl.%d" % randint(10000,99999)
        args = [
            "/usr/bin/env",
            "screen",
            "-S",
            name,
            "-d", "-m"
        ]

        if logfile is not None and type(logfile) is str:
            args.extend(["-L", "-Logfile", logfile])

        args += cmd

        result = subprocess.run(args, check=True)

        instance = FuzzerInstance()
        instance.screen_name = name

        return instance

    def terminate(self, instance):
        s = screenutils.Screen(instance.screen_name)
        if s.exists:
            s.kill()

    def status(self, instance):
        s = screenutils.Screen(instance.screen_name)
        return s.exists

    def postprocess(self, **kwargs):
        pass

class AFLGoBenchmark(FuzzerBenchmark):
    pass
