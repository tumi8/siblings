#!/usr/bin/env python3
"""
    The sibling decision algorithm.
    Can optionally print timestamps in a figure.
"""

from __future__ import division
from scipy import stats
import numpy as np
import matplotlib
matplotlib.use('Agg')  # this is not pep-conform but required here ^^
import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages
import csv
import os.path
import time
#from sys import argv
import sys
from scipy.interpolate import LSQUnivariateSpline
import pickle
from multiprocessing import Process
import multiprocessing
import time
import traceback
from collections import Counter
import logging
import argparse

"""
ppd_rng_elm = 0
ott_rng_elm = 0
ott_rng_unk = 0
"""
mixd_elm = 0  # actually used
# mixd_unk = 0  # actually used
val_slp = 0
# false postive and false negative count
false_pos = 0
false_neg = 0
true_pos = 0
true_neg = 0
neg_skew = 0
tcp_sig = 0

const_skew = 0
ipcache = dict()
objectscache = dict()


def calCDF(diff_arr):
    """"cumulative distribution function"""
    arr = diff_arr
    key_list = Counter(arr).keys()
    count_list = Counter(arr).values()
    tot = sum(count_list)
    perc = [100*(c/tot) for c in count_list]
    packed = [(i, j) for i, j in zip(key_list, perc)]
    sorted_lst = sorted(packed)
    suml = 0
    acc_sum = []
    for a, b in sorted_lst:
        suml += b
        acc_sum.append(suml)
    x = [i for i, j in sorted_lst]
    ret_list = [(i, j) for i, j in list(zip(x, acc_sum))]
    return ret_list


class Consumer(multiprocessing.Process):
    # https://pymotw.com/2/multiprocessing/communication.html
    def __init__(self, task_queue, result_queue):
        multiprocessing.Process.__init__(self)
        self.task_queue = task_queue
        self.result_queue = result_queue

    def run(self):
        proc_name = self.name
        while True:
            next_task = self.task_queue.get()
            if next_task is None:
                print('%s: Exiting' % proc_name)
                break
            else:
                a = next_task()
                self.result_queue.put(a)
                self.task_queue.task_done()
        return


class rl_calcsib(object):
    def __init__(self, np4, offset4, np6, offset6, opts4, opts6, domain, ip4, ip6):
        self.np4 = np4
        self.offset4 = offset4
        self.np6 = np6
        self.offset6 = offset6
        self.opts4 = opts4
        self.opts6 = opts6
        self.domain = domain
        self.ip4 = ip4
        self.ip6 = ip6

    def __call__(self):
        try:
            s = calcsib(self.np4, self.offset4, self.np6, self.offset6,
                        self.opts4, self.opts6,
                        self.domain, self.ip4, self.ip6)
        except Exception as e:
            logging.error("error in calcsib for {} {} {}, error: {}, np4: {}, np6: {} ".format(self.domain, self.ip4, self.ip6, e, self.np4, self.np6))
            raise
            return None
        else:
            return s


def calcsib(np4, offset4in, np6, offset6in, opts4, opts6, domain, ip4, ip6):
    s = skews()  # instantiation of skew class
    s.domain = domain
    s.ip4 = ip4
    s.ip6 = ip6
    s.opts4 = opts4
    s.opts6 = opts6
    if opts4 == opts6:
        s.optsdiff = 0
    else:
        s.optsdiff = 1
    ignore, den_arr4, errorindicator4 = s.processTrace2(np4, 4)
    ignore, den_arr6, errorindicator6 = s.processTrace2(np6, 6)
    if errorindicator4 or errorindicator6:
        logging.error("calcsib: processTrace2 indicates error, exiting for domain {}".format(s.domain))
        return s
    # check that Hz are similar
    try:
        hzdiff = abs(s.hz4-s.hz6)
    except:
        logging.error("Cannot calculate hzdiff for domain {}".format(self.domain))
        hzdiff = "ERROR"
    if abs(s.hz4 - s.hz6) > 0.1:
        logging.warning("calcsib: hz different for domain {}, hz4 {}, hz6 {}".format(s.domain, s.hz4, s.hz6))
        s.dec = "non-sibling (hz different)"
        return s

    try:
        hzr2diff = abs(s.hz4r2-s.hz6r2)
    except:
        logging.error("Cannot calculate hzr2diff for domain {}".format(self.domain))
        hzdiff = "ERROR"

    # check how close raw tcp ts values are
    td_tcpt = (s.tcp_t_offset6 - s.tcp_t_offset4)/np.mean([s.hz4, s.hz6]) # time distance between initial tcp timestamp v4/v6 in seconds
    offset4 = np.float(offset4in)/(1000*1000) # convert from microseconds to s
    offset6 = np.float(offset6in)/(1000*1000) # convert from microseconds to s
    logging.debug("calcsib: domain {}, offset6 {}, offset4 {}, td_tcpt {}".format(domain, offset6, offset4, td_tcpt))
    td_rcvt = np.float64(offset6)-np.float64(offset4) # difference in first recv_t in seconds
    s.timestamps_diff = abs(td_tcpt - td_rcvt) # difference in tcp ts in seconds

    # mean remover (second level denoising)
    if den_arr4 is None:
        #print("den_arr4 empty!")
        s.dec = "error: den_arr4 empty!"
        return s
    else:
        s.mean_cln_4 = s.meanRemover(den_arr4)

    if den_arr6 is None:
        #print("den_arr6 empty!")
        s.dec = "error: den_arr6 empty!"
        return s
    else:
        s.mean_cln_6 = s.meanRemover(den_arr6)

    # cal ppd
    ppd_arr, idx6_arr, rng = s.calppd(s.mean_cln_4, s.mean_cln_6)  # uses candidate points
    ignore, med_thresh = s.meanMedianStd(ppd_arr)


    # clean points that are two standard deviation from the median
    cln_4, cln_6, ppd_arr_cut = s.delOutliers(med_thresh, s.mean_cln_4, s.mean_cln_6, idx6_arr, ppd_arr)
    s.ppd_range = max(ppd_arr_cut) - min(ppd_arr_cut)
    # ppd_mean = np.mean(ppd_arr_cut)  # vulture says this is not used
    # ppd_median = np.median(ppd_arr_cut)  # dito

    # calculate alpha
    s.a4, ignore, ignore, s.r4_sqr = s.calAlpha(cln_4)
    s.a6, ignore, ignore, s.r6_sqr = s.calAlpha(cln_6)

    try:
        s.adiff = abs(s.a4 - s.a6)
    except Exception as e:
        logging.error("Failed to calculcate adiff for domain {} with exception {}".format(self.domain, e))
        s.adiff = "ERROR"

    try:
        s.r2diff = abs(s.r4_sqr - s.r6_sqr)
    except:
        logging.error("Failed to calculcate r2diff for domain {}".format(self.domain))
        s.r2diff = "ERROR"


    # prune otts two and half perc above and down
    sorted_pruned_otts4 = s.pruneOTTS(cln_4)
    sorted_pruned_otts6 = s.pruneOTTS(cln_6)
    s.ott4_rng = sorted_pruned_otts4[-1] - sorted_pruned_otts4[0]
    s.ott6_rng = sorted_pruned_otts6[-1] - sorted_pruned_otts6[0]
    s.ott_rng_diff = abs(s.ott4_rng - s.ott6_rng)
    s.ott_rng_diff_rel = s.ott_rng_diff / np.mean([s.ott4_rng, s.ott6_rng])

    # eliminating first and last points to compute the spline
    packed4 = cln_4[8:-8]
    packed6 = cln_6[8:-8]
    s.bin_size_4 = binEqual(packed4)
    s.bin_size_6 = binEqual(packed6)



    # spline polynomial on [No] equal pieces of skew trend
    try:
        s.spl_arr4, deriv_arr_4, xs4 = spline(s.bin_size_4, packed4)
        s.spl_arr6, deriv_arr_6, xs6 = spline(s.bin_size_6, packed6)
        s.xs4 = xs4
        s.xs6 = xs6
    except Exception as e:
        logging.error("calcsib spline exception: {}, parameters: s.bin_size_4 {} \n packed4 {} \ns.bin_size_6 {}\n packed6 {}\n".format(e, s.bin_size_4, packed4, s.bin_size_6, packed6))
        s.dec = "error: spline calculation failed!"
        return s


    mapped_diff = []  # diff between one curve and its mapped ones
    mapped, spline_mean_diff, curve = mapCurve(list(zip(xs4, s.spl_arr4)), list(zip(xs6, s.spl_arr6)))
    y_mapped = [v for u, v in mapped]
    if curve == "4":
        up_rng = min(len(y_mapped), len(s.spl_arr4))
        # mapped_diff2 = abs(y_mapped[:up_rng] - s.spl_arr4[:up_rng]) ## allegedly unused
        for i in range(up_rng):
            mapped_diff.append(abs(y_mapped[i] - s.spl_arr4[i]))
    elif curve == "6":
        up_rng = min(len(y_mapped), len(s.spl_arr6))
        for i in range(up_rng):
            mapped_diff.append(abs(y_mapped[i] - s.spl_arr6[i]))

    # cal the percentiles of diffs for two mapped curves
    cdf_arr = calCDF(mapped_diff)
    perc_85_arr = []
    for val, perc in cdf_arr:
        if 84 <= perc <= 86:
            perc_85_arr.append(val)

    # take 85 perc diff as metric
    middle_inx = int(round(len(perc_85_arr) / 2))
    try:
        s.perc_85_val = perc_85_arr[middle_inx]
    except Exception as e:
        print("calcsib failed at perc_val: " + str(e))
        logging.warning("calcsib failed at perc_val: " + str(e))
        s.dec = "error_percval!"
        return s

    s.dec = decision(s.r4_sqr, s.r6_sqr, None, s.a4, s.a6, s.ppd_range,
                     s.ott4_rng, s.ott6_rng, s.ott_rng_diff, s.perc_85_val,
                     None)
    return s


class skews():
    domain, ip4, ip6 = None, None, None
    r4_sqr = None
    r6_sqr = None
    a4 = None
    a6 = None
    ppd_range = None
    ott4_rng = None
    ott6_rng = None
    ott_rng_diff = None
    perc_85_val = None
    bin_size_4, bin_size_6 = None, None
    spl_arr4, spl_arr6, xs4, xs6 = None, None, None, None # required to plot skew lines
    hz4, hz6, tcp_t_offset4, tcp_t_offset6, hz4r2, hz6r2 = None, None, None, None, None, None # hz for clock detection (Kohno et al.)
    timestamps_diff = None # difference between raw v4 and raw v6 tcp ts
    dec = None
    ott_rng_diff_rel = None
    opts4, opts6, optsdiff = None, None, None
    hzdiff, hzr2diff, adiff, r2diff = None, None, None, None


    def calHertz(self, rcv_t, tcp_t, ver):
        """ From rec_t and tcp_t, calculate Hertz of remote clock
            hertz is slope of linear regression
            Based on Kohno 2005 paper
            ver is 4 or 6
        """

        # Calculating Offsets
        count = len(rcv_t)
        Xi_arr = np.zeros(count-1)
        Vi_arr = np.zeros(count-1)

        adjustment = 0
        for i in range(1, count-1):
            # xi = rcv_t[i] - rcv_t[0]
            xi = rcv_t[i]  # rcv_t is alreay zero-based
            if (tcp_t[i] + 1000) < tcp_t[i-1]: # non-monotonic, likely wrap-around. 1000 as safety margin to allow for e.g. packet reordering. 1000 TS ticks will typically range from 1 to 10 seconds
                if tcp_t[i-1] > 2**31:
                    logging.warning("calHertz: fixing likely tcp ts wrap-around for domain {} for timestamps {} and {}".format(
                        self.domain, tcp_t[i], tcp_t[i-1]))
                    adjustment=2**32
                else:
                    logging.error("calHertz: non-monotonic tcp ts without wrap-around {} for timestamps {} and {}".format(
                        self.domain, tcp_t[i], tcp_t[i-1]))
            vi = tcp_t[i] + adjustment - tcp_t[0]
            Xi_arr[i-1] = xi
            Vi_arr[i-1] = vi
        # rcv_t is already zero-based upon data load
        #Xi_arr = rcv_t
        slope, intercept, rval, pval, stderr = stats.linregress(Xi_arr, Vi_arr)
        hzr2 = rval*rval
        #logging.debug("calHertz: domain {} rcv_t is {}".format(self.domain, rcv_t))
        logging.debug("calHertz: domain {} count is {}, slope {}, intercept {}, hzr2 {}, pval {}, stderr {}, rcv_t1 {}, tcp_t0 {}, Xi_arr is {}, Vi_arr {}".format(
            self.domain, count, slope, intercept, hzr2, pval, stderr, rcv_t[1], tcp_t[0], None, None))
        slope = round(slope) # round to next integer according to Kohno et al, Sec. 4.3
        if ver == 4:
            self.hz4 = slope
            self.hz4r2 = hzr2
            self.tcp_t_offset4 = tcp_t[0]
            logging.debug("calhertz: domain {}, setting tcp_t_offset4 as {} based on tcp_t[:10] {}".format(self.domain, self.tcp_t_offset4, tcp_t[:10]))
        elif ver == 6:
            self.hz6 = slope
            self.hz6r2 = hzr2
            self.tcp_t_offset6 = tcp_t[0]
            logging.debug("calhertz: domain {}, setting tcp_t_offset6 as {} based on tcp_t[:10] {}".format(self.domain, self.tcp_t_offset6, tcp_t[:10]))
        else:
            logging.error("calhertz incorrectly called with ver {}".format(ver))
        return (slope, Xi_arr, Vi_arr)

    def calOffsets(self, Xi_arr, Vi_arr, hz):
        """Calculates time offsets, Xi and Vi and returns them as lists"""

        Wi_arr = [round(vi / hz, 6) for vi in Vi_arr]  # tcptimestamps in seconds with microsecond precision
        Yi_arr = [(wi - xi) * 1000 for wi, xi in zip(Wi_arr, Xi_arr)]  # offset in miliseconds
        offset_arr = [(round(x, 6), round(y, 6)) for x, y in zip(Xi_arr, Yi_arr)]
        return offset_arr

        """
    def rawOffsets(self, Xi_arr, Vi_arr):
        use raw tcp timestamps to calculate the offset array

        Yi_arr = [(vi - xi) for vi, xi in zip(Vi_arr, Xi_arr)]  # offset in miliseconds
        offset_arr = [(round(x, 6), round(y)) for x, y in zip(Xi_arr, Yi_arr)]

        return offset_arr
        """


    def meanMedianStd(self, diff_arr):
        """calculates the median,mean and the standard deviation of the pair wise point distance array"""

        mad_lst = []  # median absolute deviation
        mean = np.mean(diff_arr)  # mean (average) of the set
        std_mean = np.std(diff_arr)  # standard deviation from the mean
        median = np.median(diff_arr)  # mdian of the set

        consis_const = 1.4826  # consistency constant for a normal distribution

        for point in diff_arr:
            mad_lst.append(abs(point - median))
        std_med = consis_const * np.median(mad_lst)  # median absolute deviation*cosis_cons = standard deviation from the median of a set
        med_threshhold = (median - 2 * std_med, median + 2 * std_med)
        mean_threshhold = (mean - 2 * std_mean, mean + 2 * std_mean)  # 95.4 confidence interval

        return mean_threshhold, med_threshhold

    def calppd(self, den_arr4, den_arr6):
        """Calculate the pairwise point distance between candicate offset values for IPv4 and IPv6 and returns the absolute
        pairwise point distance array."""

        v4_X, v4_Y = zip(*den_arr4)
        v6_X, v6_Y = zip(*den_arr6)

        max_index = min(len(v4_X), len(v6_X))  # for graphs for which one of the IPs stops responding at some point (unequal ott arr size)

        np_6_X = np.array(v6_X)
        idx6_arr = []  # hold the indexes for the first for loop being the indexes for the closest IPv6 arrival times relative to every IPv4 arrival time
        ppd_arr = []  # the absoulte pariwise-point distance array

        for idx in range(max_index):  # finding the closest arrival time for v6 being sj6(here index) to that of v4 si4(closest arrival time)
            idx6 = np.abs(np_6_X - v4_X[idx]).argmin()
            idx6_arr.append(idx6)

        for idx4 in range(max_index):  # getting the Y values for those pair of points and calculating the absolute pair-wise distance
            si4 = v4_Y[idx4]
            sj6 = v6_Y[idx6_arr[idx4]]
            ppd_arr.append(abs(si4 - sj6))

        glb_min = min(min(v4_Y), min(v6_Y))
        glb_max = max(max(v4_Y), max(v6_Y))
        rng = abs(glb_min - glb_max)  # range between the smallest and greates value observed

        return ppd_arr, idx6_arr, rng

    def denoise(self, offset_arr):
        """gives the min of the y values per n seconds mentioned by "begin" and "const"."""

        measure_t, otts = zip(*offset_arr)
        all_otts = []
        all_times = []
        otts_per_h = []
        times_per_h = []
        min_arr = []
        hold_x = 0
        hold_y = 0
        ctr = 0
        n = 1
        begin = 0
        end = 120  # N refering to the amount of seconds indicating the first interval
        const = 120  # the coefficient indicating the break interval: every const seconds: must be set the same as end value
        for timel in measure_t:  # divide the points every 60 seconds (probe)
            ctr += 1
            if begin <= timel < end:
                times_per_h.append(timel)
                otts_per_h.append(otts[ctr - 1])
            else:
                hold_x = timel
                hold_y = otts[ctr - 1]
                all_times.append(times_per_h)
                all_otts.append(otts_per_h)
                times_per_h = []
                otts_per_h = []
                times_per_h.append(hold_x)
                otts_per_h.append(hold_y)  # for the next round
                begin = end
                n += 1
                end = n * const
            if ctr == len(measure_t) and otts_per_h:  # belonging to the last hour/min only going through the if statement
                all_times.append(times_per_h)
                all_otts.append(otts_per_h)

        for i in range(len(all_otts)):
            idx = np.array(all_otts[i]).argmin()
            min_per_probe = all_otts[i][idx]
            assoc_x_per_probe = all_times[i][idx]
            min_arr.append((assoc_x_per_probe, min_per_probe))

        return min_arr

    def calAlpha(self, offset_arr):
        """Calculates the slope (alpha) of the offset points which is the relative clock skew ratio"""

        time_start =time.time()
        x_arr, y_arr = zip(*offset_arr)
        r_value = stats.linregress(x_arr, y_arr)[2]
        try:
            medslope, medintercept = stats.mstats.theilslopes(y_arr, x_arr)[0:2]
        except FloatingPointError as e:
            logging.error("CRITICAL: theilslopes FloatingPointError {} for arrays y_arr {} and x_arr {} of domain {}".format(e, y_arr,x_arr, self.domain))
        except Exception as e:
            logging.error("CRITICAL: theilslopes Other error {} for arrays y_arr {} and x_arr {} of domain {}".format(e, y_arr,x_arr, self.domain))
            raise

        return medslope, medintercept, r_value, r_value**2

    def processTrace2(self, np, ver):
        tcp_t = np[:, 0]
        recv_t = np[:, 1]
        denoised_arr = []

        if not recv_t.any() or not tcp_t.any(): # TODO this is bad as it does not check for existence but rather for any values to be true
            self.dec = "error: recv_t or tcp_t empty"
            return None, None, True

        hz, Xi_arr, Vi_arr = self.calHertz(recv_t, tcp_t, ver)
        if abs(hz) < 1:
            logging.warning("processTrace2: abs(hz) < 1 for domain {}".format(self.domain))
            self.dec = "ERROR: <1hz"
            return None, None, True
        if (ver == 4 and self.hz4r2 < 0.9) or (ver == 6 and self.hz6r2 < 0.9):
            logging.warning("processTrace2: too low r-squared for fitting clock skew, failing. domain {}, r^2: v4 {} and v6 {}".format(self.domain, self.hz4r2, self.hz6r2))
            self.dec = "ERROR: too small clock hertz r-squares"
            return None, None, True
        offset_arr = self.calOffsets(Xi_arr, Vi_arr, hz)
        if offset_arr is None:
            logging.error("offset_arr empty!")
            self.dec = "ERROR: empty offset_arr"
            return None, None, True

        denoised_arr = self.denoise(offset_arr)
        if denoised_arr is None:
            print("denoised_arr empty!")
            self.dec = "error: empty offset_arr"
            return None, None, True
        return offset_arr, denoised_arr, False

    def delOutliers(self, mean_thresh, den_arr4, den_arr6, idx6_arr, ppd_arr):
        """Deletes the outliers that stand two standard deviation away from
        the mean, the result will be used
        as another level of cleaning up the graph."""
        cln4 = []
        cln6 = []
        ppd_arr_cut = []
        arr4 = den_arr4
        arr6 = []
        l_dev = mean_thresh[0]
        u_dev = mean_thresh[1]
        for idx6 in idx6_arr:
            arr6.append(den_arr6[idx6])

        for i in range(len(ppd_arr)):
            if not(ppd_arr[i] < l_dev or ppd_arr[i] > u_dev):
                cln4.append(arr4[i])
                cln6.append(arr6[i])
                ppd_arr_cut.append(ppd_arr[i])

        return cln4, cln6, ppd_arr_cut

    def pruneOTTS(self, offset_arr):
        """sorts and prunes the offset points between 2.5 and 97.5 percent for removing outliers which
        is later used to test hosts with negligible clock skew and hence undeterminable."""

        ret_arr = []
        otts = [y for x, y in offset_arr]
        sorted_arr = sorted(otts)
        size = len(otts)
        lowcut = (2.5 * size) / 100
        upcut = (97.5 * size) / 100
        low_idx = int(round(lowcut))
        up_idx = int(round(upcut)) - 1

        for it in range(low_idx, up_idx):
            ret_arr.append(sorted_arr[it])

        return ret_arr


    def meanRemover(self, offsets):
        """Getting the array of observed offsets, and the three sigma prunes outliers"""
        y_arr = [v for u, v in offsets]
        mean = np.mean(y_arr)
        std_mean = np.std(y_arr)
        mean_threshhold = (mean - 2.17009 * std_mean, mean + 2.17009 * std_mean)  # 97 confidence interval
        ret_arr = []
        up = mean_threshhold[1]
        down = mean_threshhold[0]
        for o in offsets:
            if not(o[1] < down or o[1] > up):
                ret_arr.append(o)

        return ret_arr


def plotclassfrompickle(tsfile, mode=None):
    """ plot graphics from pickled cache """
    plot_name = os.path.abspath(tsfile + ".plots.pdf")
    pp = PdfPages(plot_name)  # opening a multipage file to save all the plots
    pklfile = open(tsfile+".resultspickle", 'rb')
    d = pickle.load(pklfile)
    pklfile.close()
    count = len(d.items())
    ctr = 0
    for _, s in d.items():
        print("{} / {} plotting entry {}".format(ctr, count, s.domain))
        plotclass(pp, s)
        ctr += 1
    pp.close()
    print("Plotted to file {}".format(tsfile + ".plots.pdf"))


def plotclass(pp, s):
    """ Plots the skew sets for a pair """
    fig = plt.figure()
    ax1 = fig.add_subplot(111)

    try:
        X4, Y4 = zip(*s.mean_cln_4)
        X6, Y6 = zip(*s.mean_cln_6)
        ax1.plot(X4, Y4, 'bo', color="blue", alpha=0.4, label="IPv4")
        ax1.plot(X6, Y6, 'bo', color="red", alpha=0.4, label="IPv6")
    except Exception as e:
        print("Plotting failed for host {} with error {}".format(s.domain, e))
        pass

    try:
        ax1.plot(s.xs4, s.spl_arr4, linewidth=4, color="blue", alpha=0.4)
        ax1.plot(s.xs6, s.spl_arr6, linewidth=4, color="red", alpha=0.4)
    except Exception as e:
        print("Not plotting host {} due to exception {}".format(s.domain, e))
        pass

    plt.legend(loc='lower right')
    plt.title('Host: {} ({} / {})\n Decision: {}'.format(
        s.domain, s.ip4, s.ip6, s.dec), fontsize=10)
    plt.xlabel('measurement time (h)')
    plt.ylabel('observed offset (msec)')
    ticks = ax1.get_xticks() / 3600
    ticks = [round(t, 1) for t in ticks]
    ax1.set_xticklabels(ticks)
    # saving all in PDF
    pp.savefig(fig)
    plt.close(fig)

""" LIKELY NOT USED!!
def plot(pp, index, host, arr4, arr6, spl_arr4=None, spl_arr6=None, xs4=None, xs6=None, ppd_arr=None, threshhold=None, a4=None, b4=None, a6=None, b6=None, data=None, xs=None,
         cut_size=None, q4_1=None, q4_2=None, q4_3=None, bin_size_4=None, q6_1=None, q6_2=None, q6_3=None, bin_size_6=None, max=None, min=None, sub=None):
    X4, Y4 = zip(*arr4)
    X6, Y6 = zip(*arr6)
    y4 = []
    y6 = []

    print("plotting entry {}".format(host))
    fig = plt.figure()
    ax1 = fig.add_subplot(111)
    ax1.plot(X4, Y4, 'bo', color="blue", alpha=0.4, label="IPv4")
    ax1.plot(X6, Y6, 'bo', color="red", alpha=0.4, label="IPv6")

    #if spl_arr4 and spl_arr6:
    try:
        #print(spl_arr4, spl_arr6)
        #xs4, spl_y4 = zip(*spl_arr4)
        #xs6, spl_y6 = zip(*spl_arr6)
        ax1.plot(xs4, spl_arr4, linewidth=4, color="blue", alpha=0.4)
        ax1.plot(xs6, spl_arr6, linewidth=4, color="red", alpha=0.4)
    except Exception as e:
        print("Not plotting spline for host {} due to exception {}".format(host, e))
        pass

    if data:  # reg lines
        y4 = [a4 * xi + b4 for xi in X4]
        y6 = [a6 * xj + b6 for xj in X6]
        plt.plot(X4, y4, color="cyan", label="reg4")
        plt.plot(X6, y6, color="pink", label="reg6")

    if ppd_arr:
        if cut_size:
            X4 = [i for i, j in arr4[:cut_size]]
            plt.plot(X4, ppd_arr, "--r", color="green")
        else:
            plt.plot(X4, ppd_arr, "--r", color="green")

    if threshhold:
        lower = threshhold[0]
        upper = threshhold[1]
        plt.axhline(y=lower, xmin=0, xmax=X6[len(X6) - 1], hold=None, color="yellow", linewidth=2)
        plt.axhline(y=upper, xmin=0, xmax=X6[len(X6) - 1], hold=None, color="yellow", linewidth=2)

    if max and min:
        x_max, y_max = zip(*max)
        x_min, y_min = zip(*min)
        ax1.plot(x_max, y_max, 'bo', color="black", alpha=1, label="max")
        ax1.plot(x_min, y_min, 'bo', color="orange", alpha=1, label="min")

    if sub:
        x, y = zip(*sub)
        ax1.plot(x, y, color="purple", linewidth=4, alpha=1)

    plt.legend(loc='lower right')
    plt.title('Host: ' + host)
    plt.xlabel('measurement time (h)')
    plt.ylabel('observed offset (msec)')
    ticks = ax1.get_xticks() / 3600
    ticks = [round(t, 1) for t in ticks]
    ax1.set_xticklabels(ticks)
    # saving all in PDF
    pp.savefig(fig)
    plt.close(fig)
"""


def decision(r4_square, r6_square, theta, a4, a6, ppd_corrid, rng4, rng6,
             rng_diff, spl_diff_85, dataset=None):
    """ decison algorithm """
    passed = False
    validslope_metric = 0.81  # linear slopes obtained by r values and plots (r value of 0.9 or greater)
    rsqr_diff_metric = 0.2
    neglig_skew_metric = 1.5  # obtained from the plots
    ott_rng_diff_metric = 0.47  # obtained from cdf (whole dataset) for one negligible skew
    slope_diff_metric = 0.00005  # obtained from cdf (whole dataset)
    spline_diff_metric = 0.63  # obtained from cdf of all 85 percentiles of spline diffs
    spline_diff_ldynam_metric = 2.3  # CDF 54 percentile for both ott ranges > 14 ms
    large_ott_rng = 14  # for both v4 and v6
    final_dec = ""
    # dataset: if sib or non-sib, tp/fp calculations are available

    global false_pos
    global false_neg
    global neg_skew
    global val_slp
    global ott_rng_unk
    #global mixd_unk
    global ott_rng_elm
    global mixd_elm
    global const_skew
    global true_pos
    global true_neg

    # r_square test
    # signif rsquare with different signs
    if (r4_square >= validslope_metric and r6_square >= validslope_metric) and ((a4 < 0 and a6 > 0) or (a4 > 0 and a6 < 0)):
        const_skew += 1
        final_dec += "non-sibling(slope sign mismatch)"
        # if dataset == "sib":
        #    false_neg += 1
        # elif dataset == "non-sib":
        #    true_neg += 1

    # significant rsquare with same slope sign and small slope diff or else continue to the next step (and not clasify and non-siblings)
    elif (r4_square >= validslope_metric and r6_square >= validslope_metric) and (np.sign(a4) == np.sign(a6)) and (abs(a4 - a6) <= slope_diff_metric):
        const_skew += 1
        final_dec += "sibling(valid slope/small slope diff)"
        #if dataset == "non-sib":
        #    false_pos += 1
        #elif dataset == "sib":
        #    true_pos += 1
        val_slp += 1

    # for detecting one linear skew trend and avoiding borderline cases
    elif ((r4_square >= validslope_metric and r6_square < validslope_metric) or (r4_square <= validslope_metric and r6_square > validslope_metric)) and \
            abs(r4_square - r6_square) > rsqr_diff_metric:
        final_dec += "non-sibling(big rsqr deviation)"
        #if dataset == "sib":
        #    false_neg += 1
        #elif dataset == "non-sib":
        #    true_neg += 1

    # ott range test
    elif rng4 <= neglig_skew_metric and rng6 <= neglig_skew_metric:  # both curves with small ranges
        final_dec += "no skew(unknown)"
        # neg_skew += 1
        # ott_rng_unk += 1
        # if not passed:
        #    mixd_unk += 1

    # ott range delta
    elif ((rng4 <= neglig_skew_metric and rng6 > neglig_skew_metric) or (rng6 <= neglig_skew_metric and rng4 > neglig_skew_metric)) \
            and rng_diff > ott_rng_diff_metric:  # one curve with a small range
        final_dec += "non-sibling(one negligible and ott diff delta too large)"  # to catch the borderline cases of one significant skew
        # if dataset == "sib":
        #    false_neg += 1
        # elif dataset == "non-sib":
        #    true_neg += 1

        #ott_rng_elm += 1
        #if not passed:
        #    mixd_elm += 1

    # spline diff test
    elif spl_diff_85 <= spline_diff_metric:
        final_dec += "sibling(spline test)"
        #if dataset == "non-sib":
        #    false_pos += 1
        #elif dataset == "sib":
        #    true_pos += 1

    elif (rng4 > large_ott_rng and rng6 > large_ott_rng) and (spl_diff_85 <= spline_diff_ldynam_metric):
        final_dec += "sibling(spline test)bigrng"
        #if dataset == "non-sib":
        #    false_pos += 1
        #elif dataset == "sib":
        #    true_pos += 1

    else:
        final_dec += "non-sibling(spline test)"
        # if dataset == "sib":
        #    false_neg += 1
        # elif dataset == "non-sib":
        #    true_neg += 1

    return final_dec


def writefromclass(s, writer):
    try:
        writer.writerow([s.domain, s.ip4, s.ip6,
                        s.hz4, s.hz6, s.hzdiff,
                        s.hz4r2, s.hz6r2, s.hzr2diff,
                        s.tcp_t_offset4, s.tcp_t_offset6, s.timestamps_diff,
                        s.a4, s.a6, s.adiff,
                        s.r4_sqr, s.r6_sqr, s.r2diff,
                        s.ott4_rng, s.ott6_rng, s.ott_rng_diff, s.ott_rng_diff_rel,
                        s.opts4, s.opts6, s.optsdiff,
                        s.perc_85_val, s.dec])
    except Exception as e:
        writer.writerow([s.domain, s.ip4, s.ip6])
        print("ERROR: Printing output for domain {} failed with error {}".format(s.domain, e))
        logging.debug("ERROR: Printing output for domain {} failed with error {}".format(s.domain, e))


def startwriter(args):
    csv_path_abs = os.path.abspath(args.scfile+args.tsf + ".siblingresult.csv")

    with open(csv_path_abs, "wb"):  # purge previous file content
        pass

    # open the file for writing, write headers and pass the writer obj
    # to exportData fucntion for further writing.
    fd = open(csv_path_abs, "a")
    writer = csv.writer(fd)
    writer.writerow(["domain", "ip4", "ip6",
                     "hz4", "hz6", "hzdiff",
                     "hz4r2", "hz6r2", "hzr2diff",
                     "tcp_t_offset4", "tcp_t_offset6", "timestamps_diff",
                     "a4", "a6", "adiff",
                     "r4_sqr", "r6_sqr", "r2diff",
                     "ott4_rng", "ott6_rng", "ott_rng_diff", "ott_rng_diff_rel",
                     "opts4", "opts6", "optsdiff",
                     "perc_85_val", "decision"])
    return writer, None, fd, csv_path_abs, None


def binEqual(offsets):
    """divide offset points into x equal sizes"""
    start = offsets[0][0]
    stop = offsets[-1][0]
    bin_size = round((stop - start) / 12, 1)

    return bin_size


def polyreg(first, second, third):
    """polynomial regression on x equal pieces of the offset trend"""

    x1, y1 = zip(*first)
    x2, y2 = zip(*second)
    x3, y3 = zip(*third)

    co1 = np.polyfit(x1, y1, 3)
    co2 = np.polyfit(x2, y2, 3)
    co3 = np.polyfit(x3, y3, 3)

    return co1, co2, co3


def spline(bin_size, offsets):
    """compute piecewise polynomial splines of degree three"""
    x, y = zip(*offsets)
    xs = np.arange(x[0], x[-1], 120)

    # array of knots (with the start and end which is addes automatically 13 knots meanaing 12 pieces)
    t = [offsets[0][0] + bin_size, offsets[0][0] + bin_size * 2, offsets[0][0] + 3 * bin_size, offsets[0][0] + 4 * bin_size,
         offsets[0][0] + 5 * bin_size, offsets[0][0] + 6 * bin_size, offsets[0][0] + 7 * bin_size, offsets[0][0] + 8 * bin_size,
         offsets[0][0] + 9 * bin_size, offsets[0][0] + 10 * bin_size, offsets[0][0] + 11 * bin_size]

    # compute a spline polynomial of degree 3 over 5 equal pieces for the y points over steps of 1 sec on the x axis.
    try:
        spl = LSQUnivariateSpline(x, y, t, w=None, bbox=[None, None], k=3)
    except ValueError as e:
        logging.error("ERROR: LSQUnivariateSpline ValueError failed with error {} and params x {} y {} t {} ".format(e,x,y,t))
        raise
    spl_deriv = spl.derivative(1)  # derivative of degree one
    orig_curve = spl(xs)
    deriv_curve = spl_deriv(xs)

    return orig_curve, deriv_curve, xs


def splineDist(y1, y2):
    """Evaluate the corridor of the v4 and v6 splines"""
    a = y1
    b = y2
    # non-equivalent sizes
    u_bnd = min(len(a), len(b))
    diff_arr = []
    mad_lst = []

    for i in range(u_bnd):
        diff_arr.append(abs(a[i] - b[i]))

    # compute std from median
    median = np.median(diff_arr)
    consis_const = 1.4826  # consistency constant for a normal distribution
    for point in diff_arr:
        mad_lst.append(abs(point - median))
    std_med = consis_const * np.median(mad_lst)  # median absolute deviation*cosis_cons = standard deviation from the median of a set

    return diff_arr, median, std_med


def mapCurve(cln_4, cln_6):
    "Maps the upper curve on the lower one"

    xs4, v4_arr = zip(*cln_4)
    xs6, v6_arr = zip(*cln_6)
    mean4 = np.mean(v4_arr)
    mean6 = np.mean(v6_arr)
    mean_diff = mean4 - mean6
    up_rng = min(len(cln_4), len(cln_6))
    x_mapped = []
    y_mapped = []
    curve = ""  # which curve to use for subtracting from mapped
    time_before=time.time()

    if mean_diff > 0:
        y_mapped = v4_arr[:up_rng] - mean_diff
    else:
        y_mapped = v6_arr[:up_rng] - abs(mean_diff)
    if mean_diff >= 0:
        x_mapped = xs4[:up_rng]
        curve = "6"
    else:
        x_mapped = xs6[:up_rng]
        curve = "4"
    return zip(x_mapped, y_mapped), abs(mean_diff), curve


def argprs():
    parser = argparse.ArgumentParser()
    parser.add_argument('-s', '--scfile', action="store", dest="scfile",
                        help='the sibling candidate file, typically the '
                        'hitlist used for scanning')
    parser.add_argument('-t', '--tsfile', action="store", dest="tsfile",
                        help='the timestamps csv file')
    parser.add_argument('-o', '--tcpoptsfile', action="store", dest="optsfile",
                        help='the file with TCP options')
    parser.add_argument('--plot', dest='mode', action='store_const',
                        const="plot", default="sibling",
                        help='optional: create PDF with plots')

    args = parser.parse_args()
    args.tsp, args.tsf = os.path.split(args.tsfile)
    # logging.debug("args: scfile = {}\ntsfile = {}\noptsfile = {}\nmode  = {}".format(
    #    args.scfile, args.tsfile, args.optsfile, args.mode))
    return args


def loadts(args):
    """ loads timestamp values from csv file """
    # writing and reading pickle are both about 10x faster than reading csv
    # hence, simplify repeated execs by providing pickle file
    time_before = time.time()
    timestart=time.time()
    d = dict()  # dictionary of numpy arrays that hold timestamps per IP
    p = dict()  # dictionary of IPs, holding # timestamps per IP
    offset = dict()  # dict to hold tsval offset per IP

    try:
        pklfile = open(args.tsfile + ".pickle", 'rb')
        d, p, offset = pickle.load(pklfile)
        pklfile.close()
    except:
        print("TS pickle loading failed, loading from csv")
        logging.debug("TS pickle loading failed, loading from csv")
        with open(args.tsfile, "r") as csvfile:
            datareader = csv.reader(csvfile)
            count = 0
            for row in datareader:
                count = count+1
                try:
                    ip = row[0]
                    tcpt = row[1]
                    recvt = row[2]
                except:
                    print("Error in line " + str(count) + "of " + str(args.tsfile) + ", skipping.")
                    logging.error("Error in line " + str(count) + "of " + str(args.tsfile) + ", skipping.")
                    continue
                if ip in d:
                    if p[ip] == 9999:
                        d[ip].resize(100*1000, 2)
                    if p[ip] > 100*1000-1: # more than 100k measurements can not be a target host
                        continue
                    if ip in offset:
                        # recv_t is zero-based and scaled to be in seconds precision
                        d[ip][p[ip], :] = \
                            [np.float64(tcpt),
                             np.float64(np.uint64(recvt)-np.uint64(offset[ip]))/np.float64(1000.0*1000.0)]
                        p[ip] = p[ip] + 1
                    else:
                        print("ip not in offset dict (should never happen, exiting): " + str(ip))
                        sys.exit(1)
                else:  # ip is not in d, i.e. has not been seen before
                    d[ip] = np.zeros((10000, 2), dtype=np.float64)
                    p[ip] = 0
                    d[ip][p[ip], :] = [np.float64(tcpt), np.float64(0.0)]
                    p[ip] = p[ip]+1
                    offset[ip] = recvt
        logging.debug("timestamp np structure built after: {}, count: {} {} {}".format(time.time()-time_before, count, len(d), len(p)))
        # resize all to correct length (removes trailing zeroes)
        for ip, value in p.items():
            d[ip].resize((p[ip], 2))

        pklfile = open(args.tsfile+".pickle", 'wb')
        pickle.dump([d, p, offset], pklfile)
        pklfile.close()
    print("ts data loading done after {} seconds, hosts: {} {} ".format(time.time()-time_before, len(d), len(p)))
    logging.debug("ts data loading done after: {} {} {}".format(time.time()-time_before, len(d), len(p)))
    return d, p, offset


def startmp():
    # see https://pymotw.com/2/multiprocessing/communication.html
    tasks = multiprocessing.JoinableQueue()
    results = multiprocessing.Queue()
    num_consumers = multiprocessing.cpu_count()
    logging.debug('Creating %d consumers' % num_consumers)
    consumers = [Consumer(tasks, results) for i in range(num_consumers)]
    for w in consumers:
        w.start()
    return tasks, results, consumers


def loadsc(args, d, p, offset, tasks, results, opts, writer):
    """ iterates through the sibling candidates file
        timestamps are stored in d, p and offset
        tasks and results are MP queues
        opts is a dict with ip-> tcp options FP mapping
        writer is a writer object to export results
    """
    lfc = 0 # line fail count
    cc = 0 # cache count
    fcnov4 = 0 # no v4 fails count
    fcnov6 = 0 # no v4 fails count
    fctld = 0 # fail count too little data
    fctmd = 0
    scc = 0
    count = 0
    fc = 0
    siblingcands = dict()
    decisioncache = dict()

    with open(args.scfile) as scfile:  # iterate through sibling cands
        csvreader = csv.reader(scfile)
        rowcount = 0
        for row in csvreader:
            time_before = time.time()
            rowcount += 1
            try:
                domain = row[0]
                ip4 = row[1]
                ip6 = row[2]
            except:
                print("Reading line failed: " + str(rowcount) + "\n")
                logging.warning("Reading line failed: " + str(rowcount) + "\n")
                fc += 1
                lfc += 1
            if (ip4, ip6) in decisioncache:
                # this decision cache avoids re-running calculations in case of duplicate inputs
                logging.debug("(from cache) decision: "+ str(domain) + " "+ str(ip4) +" "+ str(ip6) +" "+ str (decisioncache[(ip4,ip6)]))
                cc += 1
                continue
            if ip4 not in d:
                logging.warning("no ipv4 values in TS: " + str(domain) +" - "+ str(ip4) + " - " +str(ip6))
                logging.warning("decision: {} {} {} no-ipv4".format(
                    domain, ip4, ip6))
                fc += 1
                fcnov4 += 1
                continue
            if ip4 not in opts or ip6 not in opts:
                logging.warning("no tcp opts found for IPs {} / {}".format(ip4, ip6))
                opts[ip4] = ""
                opts[ip6] = ""
            d[ip4].resize((p[ip4], 2))
            np4 = d[ip4]
            offset4 = offset[ip4]
            if ip6 not in d:
                logging.warning("no ipv6 values in TS: " + str(domain) + "," + str(ip4) + "," + str(ip6))
                logging.warning("decision: {} {} {} no-ipv6".format(domain, ip4, ip6))
                fc += 1
                fcnov6 += 1
                continue
            d[ip6].resize((p[ip6], 2))
            np6 = d[ip6]
            offset6 = offset[ip6]
            time_after = time.time()
            logging.debug("array sizes for "+str(domain)+" : "+str(ip4)+","+str(np4.size)+","+str(ip6)+","+str(np6.size))
            if np4.size < 100 or np6.size < 100:
                logging.debug("arry sizes too small, skipping!")
                logging.warning("decision: {} {} {} too-little-data".format(domain, ip4, ip6))
                fctld += 1  # fail count too little data
                fc += 1  # generic fail count
                continue
            if np4.size > 100*1000 or np6.size > 100*1000:
                logging.debug("arry sizes too big, skipping!")
                logging.warning("decision: {} {} {} too-much-data".format(
                    domain, ip4, ip6))
                fctmd += 1  # fail count too little data
                fc += 1
                continue

            logging.debug("calling calcsib on {} , {}, {}".format(
                domain, ip4, ip6))
            print("+", end="")
            tasks.put(rl_calcsib(np4, offset4, np6, offset6, opts[ip4], opts[ip6], domain, ip4, ip6))
            scc += 1
            # continuously take results off the output queue to keep it small
            while(tasks.qsize() > 100):
                if(results.empty()):
                    continue
                while(not results.empty()):
                    s = results.get()
                    if(not s):
                        logging.warning("no s!")
                    else:
                        decisioncache[(s.ip4, s.ip6)] = s.dec
                        objectscache[(s.ip4, s.ip6)] = s
                        logging.info("decision: {} {} {} {}".format(
                            s.domain, s.ip4, s.ip6, s.dec))
                        writefromclass(s, writer)

            count += 1
            continue

    print("\nRead {} lines from sc file {} with {} fails, {} cache decisions and {} calcsib calls. ".format(rowcount, args.scfile, fc, cc, scc))
    logging.debug("Read {} lines from sc file {} with {} fails, {} cache decisions and {} calcsib calls. ".format(rowcount, args.scfile, fc, cc, scc))
    logging.debug("fails substructured into line format: {} nov4ts: {}  nov6ts: {} too-little-data: {} tmd: {}".format(lfc, fcnov4, fcnov6, fctld, fctmd))


def loadtcpopts(args):
    # loads tcp opts from file in format
    # 1.2.3.4,MSS-SACK-TS-N-WS-7
    d = dict()
    try:
        pklfile = open(args.optsfile + ".pickle", 'rb')
        d = pickle.load(pklfile)
        pklfile.close()
    except:
        d = dict()
        with open(args.optsfile) as csvfile:  # iterate through sibling cands
            csvreader = csv.reader(csvfile)
            for row in csvreader:
                ip = row[0]
                opts = row[1]
                if ip in d:
                    if d[ip] == opts:
                        continue
                    else:
                        logging.error("CRITICAL: Multiple TCP Options for IP {}".format(ip))
                else:
                    logging.debug("Setting TCP Options {} for IP {}".format(ip, opts))
                    d[ip] = opts
        pklfile = open(args.optsfile+".pickle",'wb')
        pickle.dump(d, pklfile)
        pklfile.close()
    return d


def main():
    args = argprs()  # parse arguments
    format = '%(asctime)s - %(levelname)-7s - %(message)s'
    logging.basicConfig(filename=args.scfile+args.tsf + '.decisionlog.log',
                        level=logging.DEBUG, format=format, filemode='w')
    logging.debug(
        "args: scfile = {}\ntsfile = {}\noptsfile = {}\nmode  = {}".format(
         args.scfile, args.tsfile, args.optsfile, args.mode))

    if args.mode == "plot":
        print("plotting...")
        plotclassfrompickle(args.scfile+args.tsf, "siblings")
        sys.exit(0)
    elif args.mode == "sibling":
        pass
    else:
        print("invalid mode {}, exiting!".format(args.mode))
        sys.exit(1)

    writer, ignore, fd, csv_path_abs, logfile = startwriter(args)

    d, p, offset = loadts(args)
    opts = loadtcpopts(args)

    tasks, results, consumers = startmp()
    loadsc(args, d, p, offset, tasks, results, opts, writer)

    # tasks.join() can sometimes block to inifinity - work around
    while(tasks.qsize() > 0):
        print("tasks queue size:" + str(tasks.qsize()))
        logging.debug("tasks queue size:" + str(tasks.qsize()))
        time.sleep(1)
    print("tasks queue size:" + str(tasks.qsize()))
    logging.debug("tasks queue size:" + str(tasks.qsize()))
    time.sleep(1)
    print("results queue size: " + str(results.qsize()))
    logging.debug("results queue size: " + str(results.qsize()))
    while(results.qsize() > 0):
        s = results.get()
        if(s):
            logging.info("decision: {} {} {} {}".format(
                s.domain, s.ip4, s.ip6, s.dec))
            writefromclass(s, writer)
            objectscache[(s.ip4, s.ip6)] = s
    print("results queue size (check, must be 0): " + str(results.qsize()))
    logging.debug("results queue size: " + str(results.qsize()))
    fd.close()
    pklfileres = open(args.scfile + args.tsf + ".resultspickle", 'wb')
    # memory error here when running on large (>50k scs) files:
    pickle.dump(objectscache, pklfileres, protocol=4)
    pklfileres.close()
    print("Decision file: {}".format(
        args.scfile + args.tsf + ".siblingresult.csv"))
    print("Done, check log under {}".format(
        args.scfile + args.tsf + ".decisionlog.log"))

    for w in consumers:
        w.terminate()

if __name__ == ("__main__"):
    main()
