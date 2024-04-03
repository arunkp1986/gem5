from m5.params import *
from m5.SimObject import SimObject


class StatisticsBase(SimObject):
    type = "StatisticsBase"
    cxx_header = "base/statistics.hh"
    cxx_class = "gem5::statistics::StatisticsBase"

    max_context = Param.Unsigned(8, "Maximum number of contexts")
    max_region = Param.Unsigned(
        4,
        "Maximum number of regions,Index 0-> Total,1-> User Mode,2-> Kernel Mode",
    )
