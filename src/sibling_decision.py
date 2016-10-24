#!/usr/bin/env python3
"""
    The sibling decision algorithm.
    Can optionally print timestamps in a figure.
"""
from __future__ import division
from scipy import stats
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages
import csv
import os.path
import time
from sys import argv
import sys
from scipy.interpolate import LSQUnivariateSpline
import pickle
from multiprocessing import Process
import multiprocessing
import time
import traceback
from collections import Counter

ppd_rng_elm = 0
ott_rng_elm = 0
ott_rng_unk = 0
mixd_elm = 0
mixd_unk = 0
val_slp = 0
# false postive and false negative count for Siblings and Non-siblings respectively
false_pos = 0
false_neg = 0
true_pos = 0
true_neg = 0
neg_skew = 0
tcp_sig = 0
const_skew = 0
ipcache=dict()
decisioncache=dict()
objectscache=dict()

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
    for a,b in sorted_lst:
        suml += b
        acc_sum.append(suml)
    x = [i for i,j in sorted_lst]
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
                break;
            else:
                a=next_task()
                self.result_queue.put(a)
                self.task_queue.task_done()
        return

class rl_calcsib(object):
    def __init__ (self,np4,np6,domain,ip4,ip6):
        self.np4=np4
        self.np6=np6
        self.domain=domain
        self.ip4=ip4
        self.ip6=ip6

    def __call__(self):
        try:
            s = calcsib(self.np4,self.np6,self.domain,self.ip4,self.ip6)
        except Exception as e:
            print("error in calcsib for " + self.domain + " " +  self.ip4 + " " + self.ip6)
            print("error: " + str(e))
            traceback.print_exc()
            return None
        else:
            return s

def calcsib(np4,np6,domain,ip4,ip6):
    s = skews()  # instantiation of skew class
    s.domain=domain
    s.ip4=ip4
    s.ip6=ip6
    ignore, den_arr4 = s.processTrace2(np4)
    ignore, den_arr6 = s.processTrace2(np6)
    # mean remover (second level denoising)
    if den_arr4 is None:
        print("den_arr4 empty!")
        s.dec = "error: den_arr4 empty!"
        return s
    else:
        s.mean_cln_4 = s.meanRemover(den_arr4)

    if den_arr6 is None:
        print("den_arr6 empty!")
        s.dec = "error: den_arr4 empty!"
        return s
    else:
        s.mean_cln_6 = s.meanRemover(den_arr6)

    # cal ppd
    ppd_arr, idx6_arr, rng = s.calppd(s.mean_cln_4, s.mean_cln_6)  # uses candidate points
    ignore, med_thresh = s.meanMedianStd(ppd_arr)


    # clean points that are two standard deviation from the median
    cln_4, cln_6, ppd_arr_cut = s.delOutliers(med_thresh, s.mean_cln_4, s.mean_cln_6, idx6_arr, ppd_arr)
    s.ppd_range = max(ppd_arr_cut) - min(ppd_arr_cut)
    ppd_mean = np.mean(ppd_arr_cut)
    ppd_median = np.median(ppd_arr_cut)

    # calculate alpha
    s.a4, ignore, ignore, s.r4_sqr = s.calAlpha(cln_4)
    s.a6, ignore, ignore, s.r6_sqr = s.calAlpha(cln_6)

    # prune otts two and half perc above and down
    sorted_pruned_otts4 = s.pruneOTTS(cln_4)
    sorted_pruned_otts6 = s.pruneOTTS(cln_6)
    s.ott4_rng = sorted_pruned_otts4[-1] - sorted_pruned_otts4[0]
    s.ott6_rng = sorted_pruned_otts6[-1] - sorted_pruned_otts6[0]
    s.ott_rng_diff = abs(s.ott4_rng - s.ott6_rng)

    # eliminating first and last points to compute the spline
    packed4 = cln_4[8:-8]
    packed6 = cln_6[8:-8]
    s.bin_size_4 = binEqual(packed4)
    s.bin_size_6 = binEqual(packed6)



    # spline polynomial on [No] equal pieces of skew trend
    try:
        spl_arr_4, deriv_arr_4, xs4 = spline(s.bin_size_4, packed4)
        spl_arr_6, deriv_arr_6, xs6 = spline(s.bin_size_6, packed6)
    except:
        return

    mapped_diff = []  # diff between one curve and its mapped ones
    mapped, spline_mean_diff, curve = mapCurve(list(zip(xs4, spl_arr_4)), list(zip(xs6, spl_arr_6)))
    y_mapped = [v for u, v in mapped]
    if curve == "4":
        up_rng = min(len(y_mapped), len(spl_arr_4))
        mapped_diff2 = abs(y_mapped[:up_rng] - spl_arr_4[:up_rng])
        for i in range(up_rng):
            mapped_diff.append(abs(y_mapped[i] - spl_arr_4[i]))
    elif curve == "6":
        up_rng = min(len(y_mapped), len(spl_arr_6))
        for i in range(up_rng):
            mapped_diff.append(abs(y_mapped[i] - spl_arr_6[i]))

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
        s.dec = "error_percval!"
        return s;


    s.dec = decision(s.r4_sqr, s.r6_sqr, None, s.a4, s.a6, s.ppd_range, s.ott4_rng, s.ott6_rng, s.ott_rng_diff, s.perc_85_val, None)

    return s;

class skews():
    domain,ip4,ip6 = None , None , None
    r4_sqr = None
    r6_sqr = None
    a4 = None
    a6 = None
    ppd_range = None
    ott4_rng = None
    ott6_rng = None
    ott_rng_diff = None
    perc_85_val=None
    bin_size_4, bin_size_6 = None, None

    def calHertz(self, rcv_t, tcp_t):
        """Given the set of observed TCPtimestamp values, compute the frequency
        of the fingerprintee (Herz) which is indicated by the slope variable"""

        # Calculating Offsets
        Xi_arr = []
        Vi_arr = []

        for i in range(len(rcv_t)):
            xi = rcv_t[i] - rcv_t[0]
            vi = tcp_t[i] - tcp_t[0]
            Xi_arr.append(xi)
            Vi_arr.append(vi)
        slope = stats.linregress(Xi_arr, Vi_arr)[0]
        slope = round(slope)
        return (slope, Xi_arr, Vi_arr)

    def calOffsets(self, Xi_arr, Vi_arr, hz):
        """Calculates time offsets, Xi and Vi and returns them as lists"""

        Wi_arr = [round(vi / hz, 6) for vi in Vi_arr]  # tcptimestamps in seconds with microsecond precision
        Yi_arr = [(wi - xi) * 1000 for wi, xi in zip(Wi_arr, Xi_arr)]  # offset in miliseconds
        offset_arr = [(round(x, 6), round(y, 6)) for x, y in zip(Xi_arr, Yi_arr)]
        return offset_arr

    def rawOffsets(self, Xi_arr, Vi_arr):
        """use raw tcp timestamps to calculate the offset array"""

        Yi_arr = [(vi - xi) for vi, xi in zip(Vi_arr, Xi_arr)]  # offset in miliseconds
        offset_arr = [(round(x, 6), round(y)) for x, y in zip(Xi_arr, Yi_arr)]

        return offset_arr

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
        medslope, medintercept = stats.mstats.theilslopes(y_arr, x_arr)[0:2]

        return medslope, medintercept, r_value, r_value**2

    def exportData(self, writer, i, theta, a4, b4, r4, r_sqr4, a6, b6, r6, r_sqr6, ppd_median, ppd_mean, spline_mean_diff, ott4_rng, ott6_rng, ott_rng_diff,
                   dec, ppd_rng, perc_85_mapped_diff):
        """Exports the estimated line by the calAlpha function and the host number and IP pair to a csv file """

        writer.writerow([i, theta, a4, b4, r4, r_sqr4, a6, b6, r6, r_sqr6, ppd_median, ppd_mean, spline_mean_diff, ott4_rng, ott6_rng, ott_rng_diff,
                         ppd_rng, perc_85_mapped_diff, dec])

    def processTrace2(self, np):
        recv_t = np[:, 1]
        tcp_t = np[:, 0]
        denoised_arr = []

        if not recv_t.any() or not tcp_t.any():
            return None, None

        hz, Xi_arr, Vi_arr = self.calHertz(recv_t, tcp_t)
        # TODO: due to some circumstances Hz can be zero, causing a divide by zero in the next step
        offset_arr = self.calOffsets(Xi_arr, Vi_arr, hz)
        if offset_arr is None:
            print("offset_arr empty!")
            sys.exit(1)

        denoised_arr = self.denoise(offset_arr)
        if denoised_arr is None:
            print("denoised_arr empty!")
            sys.exit(1)
        return offset_arr, denoised_arr

    def delOutliers(self, mean_thresh, den_arr4, den_arr6, idx6_arr, ppd_arr):
        """Deletes the outliers that stand two standard deviation away from the mean, the result will be used
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


def timeStamp(writer):
    writer.writerow(["File creation time: " + time.ctime()])

def plotclassfrompickle():
    plot_name = os.path.abspath(argv[2] + ".plots.pdf")
    pp = PdfPages(plot_name)  # opening a multipage file to save all the plots
    pklfile=open(tstampscsv+".resultspickle",'rb')
    d = pickle.load(pklfile)
    pklfile.close()
    for _,s in d.items():
        plotclass(pp,s)
    pp.close()

def plotclass(pp,s):
    plot(pp, s.domain, s.domain, s.mean_cln_4, s.mean_cln_6, ppd_arr=None, threshhold=None,
         a4=None, b4=None, a6=None, b6=None, data=None, spl_arr4=None, spl_arr6=None, xs=None,
         cut_size=None, q4_1=None, q4_2=None, q4_3=None, bin_size_4=s.bin_size_4, q6_1=None,
         q6_2=None, q6_3=None, bin_size_6=s.bin_size_6, max=None, min=None, sub=None)


def plot(pp, index, host, arr4, arr6, ppd_arr=None, threshhold=None, a4=None, b4=None, a6=None, b6=None, data=None, spl_arr4=None, xs=None, spl_arr6=None,
         cut_size=None, q4_1=None, q4_2=None, q4_3=None, bin_size_4=None, q6_1=None, q6_2=None, q6_3=None, bin_size_6=None, max=None, min=None, sub=None):
    """Plots the skew sets for a pair"""
    X4, Y4 = zip(*arr4)
    X6, Y6 = zip(*arr6)
    y4 = []
    y6 = []

    print("plotting entry " + str(index))
    fig = plt.figure()
    ax1 = fig.add_subplot(111)
    ax1.plot(X4, Y4, 'bo', color="blue", alpha=0.4, label="IPv4")
    ax1.plot(X6, Y6, 'bo', color="red", alpha=0.4, label="IPv6")

    if spl_arr4 and spl_arr6:
        xs4, spl_y4 = zip(*spl_arr4)
        xs6, spl_y6 = zip(*spl_arr6)
        ax1.plot(xs4, spl_y4, linewidth=4, color="blue", alpha=0.4)
        ax1.plot(xs6, spl_y6, linewidth=4, color="red", alpha=0.4)

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
    plt.title('Host' + str(index) + ': ' + host)
    plt.xlabel('measurement time (h)')
    plt.ylabel('observed offset (msec)')
    ticks = ax1.get_xticks() / 3600
    ticks = [round(t, 1) for t in ticks]
    ax1.set_xticklabels(ticks)
    # saving all in PDF
    pp.savefig(fig)
    plt.close(fig)

def decision(r4_square, r6_square, theta, a4, a6, ppd_corrid, rng4, rng6, rng_diff, spl_diff_85, dataset=None):
    """ Theta is not used """
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
    global mixd_unk
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
        if dataset == "sib":
            false_neg += 1
        elif dataset == "non-sib":
            true_neg += 1

    # significant rsquare with same slope sign and small slope diff or else continue to the next step (and not clasify and non-siblings)
    elif (r4_square >= validslope_metric and r6_square >= validslope_metric) and ((a4 > 0 and a6 > 0) or (a4 < 0 and a6 < 0)) and (abs(a4 - a6) <= slope_diff_metric):
        const_skew += 1
        final_dec += "sibling(valid slope/small slope diff)"
        if dataset == "non-sib":
            false_pos += 1
        elif dataset == "sib":
            true_pos += 1
        val_slp += 1

    # for detecting one linear skew trend and avoiding borderline cases
    elif ((r4_square >= validslope_metric and r6_square < validslope_metric) or (r4_square <= validslope_metric and r6_square > validslope_metric)) and \
            abs(r4_square - r6_square) > rsqr_diff_metric:
        final_dec += "non-sibling(big rsqr deviation)"
        if dataset == "sib":
            false_neg += 1
        elif dataset == "non-sib":
            true_neg += 1

    # ott range test
    elif rng4 <= neglig_skew_metric and rng6 <= neglig_skew_metric:  # both curves with small ranges
        print("neg skew")
        final_dec += "no skew(unknown)"
        neg_skew += 1

        ott_rng_unk += 1
        if not passed:
            mixd_unk += 1

    # ott range delta
    elif ((rng4 <= neglig_skew_metric and rng6 > neglig_skew_metric) or (rng6 <= neglig_skew_metric and rng4 > neglig_skew_metric)) \
            and rng_diff > ott_rng_diff_metric:  # one curve with a small range
        final_dec += "non-sibling(one negligible and ott diff delta too large)"  # to catch the borderline cases of one significant skew
        if dataset == "sib":
            false_neg += 1
        elif dataset == "non-sib":
            true_neg += 1

        ott_rng_elm += 1
        if not passed:
            mixd_elm += 1

    # spline diff test
    elif spl_diff_85 <= spline_diff_metric:
        final_dec += "sibling(spline test)"
        if dataset == "non-sib":
            false_pos += 1
        elif dataset == "sib":
            true_pos += 1

    elif (rng4 > large_ott_rng and rng6 > large_ott_rng) and (spl_diff_85 <= spline_diff_ldynam_metric):
        final_dec += "sibling(spline test)bigrng"
        if dataset == "non-sib":
            false_pos += 1
        elif dataset == "sib":
            true_pos += 1

    else:
        final_dec += "non-sibling(spline test)"
        if dataset == "sib":
            false_neg += 1
        elif dataset == "non-sib":
            true_neg += 1

    return final_dec


def preamble2():
    csv_path_abs = os.path.abspath(argv[2] + ".siblingresult.csv")
    logfile = open(os.path.abspath(argv[2] + ".skewalgolog.txt"),"w")
    plot_name = os.path.abspath(argv[2] + ".plots.pdf")
    pp = PdfPages(plot_name)  # opening a multipage file to save all the plots

    with open(csv_path_abs, "wb"):  # purge previous file content
        pass

    # open the file for writing, write headers and pass the writer obj to exportData fucntion for further writings.
    fd = open(csv_path_abs, "a")
    writer = csv.writer(fd)
    writer.writerow(["domain", "ip4", "ip6", "alpha4", "beta4", "r_value4", "r_square4", "alpha6", "beta6", "r_value6", "r_square6",
                     "median of ppd", "mean of ppd", "spline_mean_diff", "ott4_range", "ott6_range", "ott_rng_diff", "ppd corridor",
                     "85perc_mapped_diff", "decision"])

    return writer, pp, fd, csv_path_abs, logfile


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
    spl = LSQUnivariateSpline(x, y, t, w=None, bbox=[None, None], k=3)
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


if __name__ == ("__main__"):
    count=0
    rowcount=0
    if len(sys.argv) != 2 + 1:
        print("Usage: file.py sibling-cands tstamps")
        exit(1)
    siblingcandscsv = sys.argv[1]
    tstampscsv = sys.argv[2]
    spl_mapped_diff_85 = []
    writer, pp, fd, csv_path_abs, logfile = preamble2()
    d=dict() # dictionary of numpy arrays that hold timestamps per IP
    p=dict() # dictionary of IPs, holding # timestamps per IP
    offset=dict()

    # writing and reading pickle are both about 10x faster than reading csv
    # hence, simplify repeated execs by providing pickle file
    time_before = time.time()
    timestart=time.time()
    try:
        pklfile=open(tstampscsv+".cpickle",'rb')
        d,p,offset = pickle.load(pklfile)
        pklfile.close()
    except:
        print("loading from pickle failed, loading from csv")
        with open(tstampscsv, "r") as csvfile:
            datareader = csv.reader(csvfile)
            count = 0
            for row in datareader:
                count = count+1
                try:
                    ip = row[0]
                    tcpt = row[1]
                    recvt = row[2]
                except:
                    print("Error in line " + str(count) + "of " + str(tstampscsv) + ", skipping.")
                    logfile.write("Error in line " + str(count) + "of " + str(tstampscsv) + ", skipping.\n")
                    continue
                if ip in d:
                    if p[ip] == 9999 :
                        d[ip].resize(100*1000,2)
                    if p[ip] > 100*1000-1: # more than 100k measurements can not be a target host
                        continue
                    if ip in offset:
                        d[ip][p[ip], :] = \
                            [np.float64(tcpt),np.float64(np.uint64(recvt)-np.uint64(offset[ip]))/np.float64(1000.0*1000.0)]
                        p[ip] = p[ip]+1
                    else:
                        print("ip not in offset dict (should never happen): " + str(ip))
                        d[ip] = {}
                        p[ip] = {}
                        continue
                else:
                    d[ip] = \
                        np.zeros((10000,2),dtype=np.float64)
                    p[ip] = 0
                    d[ip][p[ip], :] = [np.float64(tcpt),np.float64(0.0)]
                    p[ip] = p[ip]+1
                    offset[ip] = recvt
        print("np structure built after: " + str(time.time()-time_before), "count: ", count, len(d), len(p))
        # resize all to correct length
        for ip, value in p.items():
            d[ip].resize((p[ip],2))

        print("resized after: " + str(time.time()-time_before), "count: ", count, len(d), len(p))
        pklfile=open(tstampscsv+".cpickle",'wb')
        # py3 automatically uses cpickle
        pickle.dump([d,p,offset],pklfile)
        print("cpickle dumped after: " + str(time.time()-time_before), "count: ", count, len(d), len(p))
        pklfile.close()
    print("data loading done after: " + str(time.time()-time_before), len(d), len(p))

    # see https://pymotw.com/2/multiprocessing/communication.html
    tasks = multiprocessing.JoinableQueue()
    results = multiprocessing.Queue()
    num_consumers = multiprocessing.cpu_count()
    print('Creating %d consumers' % num_consumers)
    consumers = [ Consumer(tasks, results) for i in range(num_consumers) ]
    for w in consumers:
        w.start()

    # write calculation results to pickle
    pklfileres=open(tstampscsv+".resultspickle",'wb')

    with open(sys.argv[1]) as scfile:
        csvreader = csv.reader(scfile)
        for row in csvreader:
            time_before = time.time()
            rowcount=rowcount+1
            try:
                domain = row[0]
                ip4 = row[1]
                ip6 = row[2]
            except:
                print("Reading line failed: " +str(rowcount) + "\n")
            if (ip4,ip6) in decisioncache:
                print("decision from cache ,", domain, ip4, ip6, decisioncache[(ip4,ip6)])
                logfile.write("decision from cache, "+ str(domain) + str(ip4) + str(ip6) + str (decisioncache[(ip4,ip6)])+"\n")
                continue
            if ip4 not in d:
                logfile.write("no ipv4 value ," + str(domain) +" - "+ str(ip4) + " - " +str(ip6) + "\n")
                continue;
            d[ip4].resize((p[ip4],2))
            np4=d[ip4]
            if ip6 not in d:
                logfile.write("no ipv6 value ," +str(domain) + ","+ str(ip4)+","+str(ip6)+"\n")
                continue;
            d[ip6].resize((p[ip6],2))
            np6=d[ip6]
            time_after = time.time()
            logfile.write("sizes,"+str(domain)+","+str(ip4)+","+str(np4.size)+","+str(ip6)+","+str(np6.size)+"\n")
            logfile.write("calling calcsib on ,"+str(domain)+","+str(ip4)+ ","+str(ip6)+ "\n")
            print("+",end="")
            tasks.put(rl_calcsib(np4,np6,domain,ip4,ip6))


            while(tasks.qsize() > 100):
                if(results.empty()):
                    continue
                while(not results.empty()):
                    s = results.get()
                    if(not s):
                        print("no s!")
                    else:
                        decisioncache[(s.ip4,s.ip6)] = s.dec
                        objectscache[(s.ip4,s.ip6)] = s
                        print("decision: ", s.domain , s.ip4 ,  s.ip6, s.dec)
                        logfile.write("decision: , "+ str(s.domain) + str(s.ip4) + str(s.ip6) + str(s.dec)+"\n")
                        writer.writerow([s.domain, s.ip4, s.ip6, s.a4, None, None, s.r4_sqr, s.a6, None, None, s.r6_sqr,
                                        None, None, None, s.ott4_rng, s.ott6_rng,
                                        s.ott_rng_diff, None, s.perc_85_val, s.dec])

            count=count+1
            continue
            # for testing purposes
            print("elapsed time:", time_after - time_before)
            print("pdd range eliminated", ppd_rng_elm)
            print("ott range eliminated", ott_rng_elm)
            print("ott range unknown", ott_rng_unk)
            print("mixed factor eliminator", mixd_elm)
            print("mixed factor unknown", mixd_unk)
            print("valid slope count", val_slp)
            print("false positive: ", false_pos)
            print("true positive: ", true_pos)
            print("false negative: ", false_neg)
            print("true negative: ", true_neg + tcp_sig)
            print("negligibel skew: ", neg_skew)
            print("tcp signature withdrawal count:", tcp_sig)
            print("linear offset trend", const_skew)

    # tasks.join() can sometimes block to inifinity - work around
    while(tasks.qsize()>0):
        print("tasks queue size:" + str(tasks.qsize()))
        time.sleep(1)
    print("tasks queue size:" + str(tasks.qsize()))
    time.sleep(1)
    print("results queue size: " + str(results.qsize()))
    while(results.qsize()>0):
        s = results.get()
        if(s):
            writer.writerow([s.domain, s.ip4, s.ip6, s.a4, None, None, s.r4_sqr, s.a6, None, None, s.r6_sqr,
                            None, None, None, s.ott4_rng, s.ott6_rng,
                            s.ott_rng_diff, None, s.perc_85_val, s.dec])
            objectscache[(s.ip4,s.ip6)] = s
        else:
            print("s empty!")
    print("results queue size: " + str(results.qsize()))
    pickle.dump(objectscache,pklfileres)
    pklfileres.close()
    fd.close()
    pp.close()

    for w in consumers:
        w.terminate()
