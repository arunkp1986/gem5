/*
 * Copyright (c) 2003-2005 The Regents of The University of Michigan
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met: redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer;
 * redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution;
 * neither the name of the copyright holders nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef __BASE_STATS_INFO_HH__
#define __BASE_STATS_INFO_HH__

#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "base/compiler.hh"
#include "base/flags.hh"
#include "base/stats/types.hh"
#include "base/stats/units.hh"

namespace gem5
{

namespace statistics
{

typedef uint16_t FlagsType;
typedef gem5::Flags<FlagsType> Flags;

/** Nothing extra to print. */
const FlagsType none =          0x0000;
/** This Stat is Initialized */
const FlagsType init =          0x0001;
/** Print this stat. */
const FlagsType display =       0x0002;
/** Print the total. */
const FlagsType total =         0x0010;
/** Print the percent of the total that this entry represents. */
const FlagsType pdf =           0x0020;
/** Print the cumulative percentage of total upto this entry. */
const FlagsType cdf =           0x0040;
/** Print the distribution. */
const FlagsType dist =          0x0080;
/** Don't print if this is zero. */
const FlagsType nozero =        0x0100;
/** Don't print if this is NAN */
const FlagsType nonan =         0x0200;
/** Print all values on a single line. Useful only for histograms. */
const FlagsType oneline =       0x0400;

/** Mask of flags that can't be set directly */
const FlagsType __reserved =    init | display;

struct StorageParams;
struct Output;

class Info
{
  public:
    /** The name of the stat. */
    std::string name;
    /** Maximum regions allowed for this stat. */
    int maxRegions;
    /** Maximum contexts allowed for this stat. */
    int maxContexts;
    /** Is region enabled*/
    int reg_enable;
    /** The separator string used for vectors, dist, etc. */
    static std::string separatorString;
    /** The unit of the stat. */
    const units::Base* unit = units::Unspecified::get();
    /** The description of the stat. */
    std::string desc;
    /** The formatting flags. */
    Flags flags;
    /** The display precision. */
    int precision;
    /** A pointer to a prerequisite Stat. */
    const Info *prereq;
    /**
     * A unique stat ID for each stat in the simulator.
     * Can be used externally for lookups as well as for debugging.
     */
    static int id_count;
    int id;

  private:
    std::unique_ptr<const StorageParams> storageParams;

  public:
    Info();
    virtual ~Info();

    /**
     * Set the name of this statistic. Special handling must be done when
     * creating an old-style statistic (i.e., stats without a parent group).
     *
     * @param name The new name.
     * @param old_style Whether we are using the old style.
     */
    void setName(const std::string &name, bool old_style=true);

    void setSeparator(std::string _sep) { separatorString = _sep;}

    void setMaxRegions(int regions) { maxRegions = regions; }
    void setMaxContexts(int ctx_id) { maxContexts = ctx_id; }
    void setregenable(int enable) { reg_enable = enable; }

    /**
     * Getter for the storage params. These parameters should only be modified
     * using the respective setter.
     * @sa setStorageParams
     */
    StorageParams const* getStorageParams() const;
    /** Setter for the storage params. */
    void setStorageParams(const StorageParams *const params);

    /**
     * Check that this stat has been set up properly and is ready for
     * use
     * @return true for success
     */
    virtual bool check() const = 0;
    bool baseCheck() const;

    /**
     * Enable the stat for use
     */
    virtual void enable();

    /**
     * Prepare the stat for dumping.
     */
    virtual void prepare() = 0;

    /**
     * Reset the stat to the default state.
     */
    virtual void reset() = 0;

    /**
     * @return true if this stat has a value and satisfies its
     * requirement as a prereq
     */
    virtual bool zero() const = 0;

    /**
     * Visitor entry for outputing statistics data
     */
    virtual void visit(Output &visitor) = 0;

    /**
     * Checks if the first stat's name is alphabetically less than the second.
     * This function breaks names up at periods and considers each subname
     * separately.
     * @param stat1 The first stat.
     * @param stat2 The second stat.
     * @return stat1's name is alphabetically before stat2's
     */
    static bool less(Info *stat1, Info *stat2);
};

class ScalarInfo : public Info
{
  public:
    virtual Counter value() const = 0;
    virtual Result result() const = 0;
    virtual Result result(int ctx_id,int region_id) const = 0;
    virtual Result total() const = 0;
};

class VectorInfo : public Info
{
  public:
    /** Names and descriptions of subfields. */
    std::vector<std::string> subnames;
    std::vector<std::string> subdescs;

  public:
    void enable();

  public:
    virtual size_type size() const = 0;
    virtual const VCounter &value() const = 0;
    virtual const VResult &result() const = 0;
    virtual const VResult &result_region(int ctx_id,int region_id) const = 0;
    virtual Result total() const = 0;
    virtual Result total_region(int ctx_id, int region_id) const = 0;
};

class DistInfo : public Info
{
  public:
    /** Local storage for the entry values, used for printing. */
    DistData data;
};

class VectorDistInfo : public Info
{
  public:
    std::vector<DistData> data;

    /** Names and descriptions of subfields. */
    std::vector<std::string> subnames;
    std::vector<std::string> subdescs;
    void enable();

  protected:
    /** Local storage for the entry values, used for printing. */
    mutable VResult rvec;

  public:
    virtual size_type size() const = 0;
};

class Vector2dInfo : public Info
{
  public:
    /** Names and descriptions of subfields. */
    std::vector<std::string> subnames;
    std::vector<std::string> subdescs;
    std::vector<std::string> y_subnames;

    size_type x;
    size_type y;

    /** Local storage for the entry values, used for printing. */
    mutable VCounter cvec;

    void enable();

    virtual Result total() const = 0;
};

class FormulaInfo : public VectorInfo
{
  public:
    virtual std::string str() const = 0;
};

class SparseHistInfo : public Info
{
  public:
    /** Local storage for the entry values, used for printing. */
    SparseHistData data;
};

typedef std::map<std::string, Info *> NameMapType;
NameMapType &nameMap();

} // namespace statistics
} // namespace gem5

#endif // __BASE_STATS_INFO_HH__
