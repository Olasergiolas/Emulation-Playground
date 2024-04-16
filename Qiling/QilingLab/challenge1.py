from qiling import Qiling
from qiling.const import QL_VERBOSE

if __name__ == "__main__":
    # set up command line argv and emulated os root path
    argv = [r'qilinglab-aarch64']
    rootfs = r'../rootfs-master/arm64_linux/'

    # instantiate a Qiling object using above arguments and set emulation verbosity level to DEBUG.
    ql = Qiling(argv, rootfs, verbose=QL_VERBOSE.DISABLED)

    # do the magic!
    ql.run()