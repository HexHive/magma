from fuzzer import Fuzzer, FuzzerBenchmark, FuzzerInstance, TargetProgram
import os
import subprocess
import shutil
from random import randint
import screenutils

class honggfuzzFuzzer(Fuzzer):
    def __init__(self, install_dir):
        super().__init__()

        self.install_dir = install_dir

        self.cc = os.path.join(self.install_dir, "hfuzz_cc", "hfuzz-gcc")
        self.cxx = os.path.join(self.install_dir, "hfuzz_cc", "hfuzz-g++")
        self.ass = "/usr/lib/as"
        self.fuzz = os.path.join(self.install_dir, "honggfuzz")

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
            "patch",
            target_name
        ]
        env["CC"] = self.cc
        env["CXX"] = self.cxx
        env["AS"] = self.ass

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
        COV_DIR = "coverage"
        CRS_DIR = "crashes"
        try:
            os.mkdir(findings_dir)
            os.mkdir(os.path.join(findings_dir,COV_DIR))
            os.mkdir(os.path.join(findings_dir,CRS_DIR))
        except:
            pass

        fuzz_cmd = "{fuzz} -f {seeds_dir} -z -t 0.02 -n 1 --covdir_all {findings_dir}/{COV_DIR} -W {findings_dir}/{CRS_DIR}{args} -- {target_path} {target_args}".format(
                fuzz = self.fuzz,
                seeds_dir = seeds_dir,
                findings_dir = findings_dir,
                args = " %s" % args if (args is not None and args != "") else "",
                target_path = target["path"],
                target_args = target["args"].replace("@@", "___FILE___")
            )
        cmd = "/usr/bin/env timeout -s INT {timeout}s {fuzz_cmd}".format(
                timeout = timeout,
                fuzz_cmd = fuzz_cmd
            ).split(" ")
        name = "honggfuzz.%d" % randint(10000,99999)
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

class hongfuzzBenchmark(FuzzerBenchmark):
    pass
