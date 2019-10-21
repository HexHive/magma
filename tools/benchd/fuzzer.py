from abc import ABC, abstractmethod
import os
from random import randint
import multiprocessing.pool
from monitor import run_monitor
import itertools

MAGMA_DIR = os.path.abspath(os.path.join(os.path.dirname(os.path.realpath(__file__)), "../../"))

for _,_,files in os.walk(os.path.join(MAGMA_DIR, "patches", "bugs")):
    files.sort()
    # the number of elements in the shared object
    MAGMA_LENGTH = int(files[-1][:files[-1].index(".patch")]) + 1
    break

class TargetProgram(dict):
    '''
    An empty class to be used as a data structure for storing target binary
    parameters.

    E.g:
    Angora compiles two binaries for every target: USE_FAST and USE_TRACK.
    Both binaries must be supplied to the fuzzer when launching a campaign.
    '''
    pass

class FuzzerInstance(dict):
    '''
    An empty class to be used as a data structure for storing parameters
    identifying a running fuzzer instance.

    E.g:
    After launching AFL, the process ID of AFL can be used to check the
    livelihood of the process and send a signal to terminate it.
    '''
    pass

class Fuzzer(ABC):

    def __init__(self):
        super().__init__()

        self.magma_dir = MAGMA_DIR

    @abstractmethod
    def compile(self, target_name, output_dir, **env):
        '''
        Compiles the Magma benchmark using the fuzzer's specified compiling
        procedure. This mainly involves setting the CC, CXX, CFLAGS, and
        CXXFLAGS environment variables, among other fuzzer-specific parameters.

        Parameters
        ----------
        output_dir:
            The location to which the compiled binaries should be copied.

        **env:
            Key-value pairs of environment variables to set when compiling the
            benchmark.

        Return
        ------
        A list of TargetProgram objects.
        '''
        pass

    @abstractmethod
    def preprocess(self, **kwargs):
        '''
        Launches the fuzzer's preprocessing routines. This method is optional
        and specific to every fuzzer.

        E.g:
        NEUZZ requires to run a training phase to generate the neural network
        model to be used during the campaign.

        Parameters
        ----------
        **kwargs:
            Key-value pairs of parameters that are needed by the preprocessing
            phase.

        Return
        ------
        None
        '''
        pass

    @abstractmethod
    def launch(self, target, seeds_dir, findings_dir, args="", timeout=86400, logfile=None):
        '''
        Launches a fuzzing campaign for the specified time duration.

        Parameters
        ----------
        target:
            A TargetProgram object supplying parameters needed by the fuzzer.
            The target's command-line options are expected to be stored in
            `target.args` as a string.

        seeds_dir:
            The path to the directory which contains the seed files.

        findings_dir:
            The path to the directory where the fuzzer will store its results.

        args:
            A command-line string of extra arguments to supply to the fuzzer.

        timeout:
            The duration, in seconds, to run the fuzzing campaign.

        Return
        ------
        A FuzzerInstance object.
        '''
        pass

    @abstractmethod
    def terminate(self, instance):
        '''
        Terminates a fuzzing campaign.

        Parameters
        ----------
        instance:
            A FuzzingInstance object.

        Return
        ------
        None
        '''
        pass

    @abstractmethod
    def status(self, instance):
        '''
        Checks the status of the fuzzer instance. Returns True if it's still
        running; False otherwise.

        Parameters
        ----------
        instance:
            A FuzzingInstance object.

        Return
        ------
        Boolean [True | False]
        '''
        pass

    @abstractmethod
    def postprocess(self, **kwargs):
        '''
        Launches the fuzzer's postprocessing routines. This method is optional
        and specific to every fuzzer.

        Parameters
        ----------
        **kwargs:
            Key-value pairs of parameters that are needed by the postprocessing
            phase.

        Return
        ------
        None
        '''
        pass

class FuzzerBenchmark:
    '''
    The FuzzerBenchmark class is responsible for preparing the campaigns to be
    launched by a specific fuzzer.
    '''

    def __init__(self, fuzzer, work_dir, trials=3, timeout=86400, args="",
            fatal=False, exclude_targets=None, **env):
        '''
        Constructs a FuzzerBenchmark object.

        Parameters
        ----------
        fuzzer:
            A Fuzzer object. This is the fuzzer to be evaluated.

        work_dir:
            An empty (non-existing) directory to be used as a scratch space while
            running the benchmark.

        trials:
            The number of times to evaluate the fuzzer against each program.

        timeout:
            The duration of time (in seconds) to run each campaign for.

        args:
            A string of extra command-line arguments to be passed to the fuzzer.

        fatal:
            Boolean. Indicates whether the canaries should be compiled in ISAN
            mode.

        env:
            Key-value pairs to use as additional environment variables during
            compilation.
        '''
        self.fuzzer = fuzzer
        self.work_dir = work_dir
        self.trials = trials
        self.timeout = timeout
        self.args = args
        self.exclude_targets = exclude_targets
        self.env = env

        if fatal:
            self.env["MAGMA_ISAN"] = "1"

        os.mkdir(self.work_dir)

    @property
    def campaigns(self):
        '''
        A generator routine. Generates all the Campaign objects to evaluate the
        fuzzer.
        '''
        targets = {
            "libpng16": [("readpng", "@@")],
            "libtiff4": [("tiffcp", "-i @@ /dev/null")],
            "libxml2": [("xmllint", "--valid --oldxml10 --push --memory @@")],
            "poppler": [("pdfimages", "@@ /tmp/out"), ("pdftoppm", "-mono -cropbox @@")]
        }

        for x in self.exclude_targets or []:
            targets.pop(x)

        for i in range(self.trials):
            for target_name, target_programs in targets.items():
                for target_program in target_programs:
                    campaign_id = "{fuzzer_name}_{target_name}_{target_program}_{trial}_{uid}".format(
                        fuzzer_name = type(self.fuzzer).__name__,
                        target_name = target_name,
                        target_program = target_program[0],
                        trial = i,
                        uid = randint(10000,99999)
                    )

                    campaign_dir = os.path.join(self.work_dir, campaign_id)
                    os.mkdir(campaign_dir)

                    output_dir = os.path.join(campaign_dir, "bin")
                    os.mkdir(output_dir)

                    tmp = self.fuzzer.compile(target_name, output_dir, MAGMA_STORAGE=campaign_id, **self.env)
                    target = next(filter(lambda t: t["program"] == target_program[0], tmp), None)
                    assert target is not None, "Could not find suitable target."
                    target["args"] = target_program[1]

                    findings_dir = os.path.join(campaign_dir, "findings")
                    seeds_dir = os.path.join(MAGMA_DIR, "seeds", target_name)

                    campaign = Campaign(campaign_id, self.fuzzer, target, campaign_dir, seeds_dir, findings_dir, self.args, self.timeout)
                    yield campaign


class Campaign:
    def __init__(self, cid, fuzzer, target, work_dir, seeds_dir, findings_dir, args=None, timeout=86400):
        self.cid = cid
        self.fuzzer = fuzzer
        self.target = target
        self.work_dir = work_dir
        self.seeds_dir = seeds_dir
        self.findings_dir = findings_dir
        self.args = args
        self.timeout = timeout

class Scheduler:
    def __init__(self, job_count):
        self.njob = job_count
        self.benchmarks = []

    def add_benchmark(self, benchmark):
        self.benchmarks.append(benchmark)

    def start(self):
        def _run_campaign(c):
            log_file = os.path.join(c.work_dir, "log.txt")
            inst = c.fuzzer.launch(c.target, c.seeds_dir, c.findings_dir, args=c.args, timeout=c.timeout, logfile=log_file)

            # monitor config
            output_file = os.path.join(c.work_dir, "monitor.txt")
            interval = 5000
            count = c.timeout // (interval // 1000)
            run_monitor(c.cid, MAGMA_LENGTH, output_file, interval=interval, count=count, force=False)

        cgen = (c for b in self.benchmarks for c in b.campaigns)
        pool = multiprocessing.pool.ThreadPool(processes=self.njob)

        while pool.map(_run_campaign, itertools.islice(cgen, self.njob)):
            pass