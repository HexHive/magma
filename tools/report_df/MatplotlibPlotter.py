from Metric import Metric
from BenchmarkData import BenchmarkData
import DataProcessing
from matplotlib.lines import Line2D
import matplotlib
from matplotlib import colors
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
import numpy as np
import seaborn as sns
import scikit_posthocs as sp
import pandas as pd
import os

def expected_time_to_trigger(bd):
    """
    Represents the "hardness" of each triggered bug in a heatmap
    by computing the expected time to trigger for each bug

    :param bd: { A BenchmarkData object loaded from experiment summary file }
    :type  bd: { BenchmarkData }
    """

    ett, agg = DataProcessing.expected_time_to_trigger_data(bd)

    #Compute the order of the fuzzer that found the most bugs in descending order
    fuzzer_order = DataProcessing.number_of_unique_bugs_found_data(bd)
    fuzzer_order = fuzzer_order.sort_values(by=['Bugs'],ascending = False) \
                               .reset_index()['Fuzzer'].tolist()

    #Sort the bug by aggregate time
    ett['Aggregate'] = agg
    ett.sort_values(by='Aggregate', inplace=True)
    ett = ett.drop(labels='Aggregate', axis=1)
    #Reordering the fuzzers
    ett = ett[fuzzer_order]
    fuzzer_label = list(ett.columns)
    bug_label  = list(ett.index)
    annotations = ett.copy()
    annotations[fuzzer_label] = annotations[fuzzer_label].applymap(lambda x : pp_time(x))
    fig, ax = plt.subplots(figsize=(10,10))
    plt.yticks(rotation=0)
    #Norm factor has to been precomputed
    heat_map = sns.heatmap(np.array(ett),cmap='seismic',
                            xticklabels=fuzzer_label,
                            yticklabels=bug_label,
                            annot=np.array(annotations),
                            fmt='s',
                            norm=colors.PowerNorm(gamma=0.32),
                            ax=ax)
    #Color bar properties
    max_num_trials = bd.get_frame().reset_index().groupby('Fuzzer')['Campaign'] \
                       .nunique().max()
    xticks = list_ticks(bd.get_campaign_duration() * max_num_trials)[4:]
    xticklables = list(map(lambda x: pp_time(x), xticks))

    cbar = ax.collections[0].colorbar
    cbar.set_ticks(xticks)
    cbar.set_ticklabels(xticklables)
    ax.patch.set(fill='True',color='darkgrey')
    ax.set_title("Expected time-to-trigger-bug for each fuzzer", fontsize =20)
    ax.xaxis.tick_top()
    fig.savefig(os.path.join('output', 'data', 'expected_time_to_bug_heat.svg'))
    plt.close()

def unique_bugs_per_library(bd, metric, libraries=None, symmetric=False, ncols=3):
    """
    Creates a 2D array plot representing the statistical significance
    between every pair of fuzzers on a target libary

    :param bd: { A BenchmarkData object loaded from experiment summary file }
    :type  bd: { BenchmarkData }

    :param libraries: { The targets to plot the statistical significance from }
    :type  libraries: { list }

    :param symmetric: { masks the upper-triangle of the table }
    :type  symmetric: { boolean }
    """

    unique_bugs, _, p_values = DataProcessing.unique_bugs_per_library_data(bd, metric)

    #If there is no library as argument we compute the plot for every fuzzer
    all_libraries = bd.get_all_targets()
    if libraries :
        drop_libraries = set(all_libraries).difference(libraries)
        unique_bugs.drop(level='Library', labels=drop_libraries, inplace=True)
        p_values.drop(level='Library', labels=drop_libraries, inplace=True)
    else:
        libraries = all_libraries

    nrows = (len(libraries) - 1) // ncols + 1
    fig, axs = plt.subplots(nrows=nrows, ncols=ncols, figsize=(12, 12), squeeze=False)

    for library, ax in zip(libraries, axs.flat):
        lib_data = p_values.xs(library, level='Library', drop_level=True)
        # maintain symmetry by removing "extra" fuzzers
        lib_data = lib_data.transpose().reindex(lib_data.index)

        heatmap_plot(lib_data, symmetric=symmetric, axes=ax, labels=False, \
            cbar_ax_bbox=[1, 0.4, 0.02, 0.2])

        ax.set_title(library)
        # axes.get_yaxis().set_visible(False)

    for ax in axs.flat[len(libraries):]:
        fig.delaxes(ax)

    fig.tight_layout(pad=2.0)
    fig.savefig(os.path.join('output', 'data', 'signplot.svg'),
                bbox_inches='tight')

    fig, ax = plt.subplots(figsize=(20, 10))
    unique_bugs.groupby(['Fuzzer','Library']) \
               .mean().unstack(0) \
               .plot.bar(width=0.8,
                         ax=ax,
                         yerr=unique_bugs.groupby(['Fuzzer','Library']) \
                                         .std().unstack(0)
                )
    ax.legend(loc='upper left', bbox_to_anchor=(1,1))
    ax.set_ylabel("Bugs Triggered")
    ax.set_xlabel("Targets")
    ax.set_xticklabels(ax.get_xticklabels(), rotation=0)
    fig.savefig(os.path.join('output', 'data', 'unique_bugs.svg'),
                bbox_inches='tight')
    plt.close()

def bug_metric_boxplot(bd, fuzzer, library, metric):
    """
    Create box plot graph showing the time distribution
    of bugs who satisfid the metric

    :param bd: { A BenchmarkData object loaded from experiment summary file }
    :type  bd: { BenchmarkData }

    :param fuzzer: { From which fuzzer }
    :type  fuzzer: { string }

    :param library: { From which library }
    :type  library: { string }

    :param metric: { chosen metric }
    :type  metric: { string }
    """

    df = DataProcessing.bug_list(bd, fuzzer, library, metric)

    #We increase the width so smaller boxes can be seen
    boxprops = dict(linestyle='-', linewidth=2, color='k')
    df.transpose().boxplot(figsize=(12, 10), boxprops=boxprops, vert=False)
    plt.title(metric + ". Fuzzer: " + fuzzer + ". Library:" + library)
    plt.ylabel("Bug Number")
    plt.xlabel("Time (seconds)")
    plt.ylim(bottom=0)
    name = f'box_{fuzzer}_{library}_{metric}.svg'
    plt.savefig(os.path.join('output', 'data', name),
                bbox_inches='tight')
    plt.close()

def line_plot_unqiue_bugs(bd, fuzzers, library, metric) :
    """
    Creates a line plot for each fuzzer,target pair
    If fuzzers is empty then a plot for every known fuzzer will be computed

    :param bd: { A BenchmarkData object loaded from experiment summary file }
    :type  bd: { BenchmarkData }

    :param fuzzers: { list of fuzzer names }
    :type  fuzzers: { list }

    :param library: { target used to compute the line plots }
    :type  library: { string }

    :param metric: { chosen metric }
    :type  metric: { string }

    """

    # TODO something's broken here, fix it

    df, x_max, y_max, x_min = DataProcessing.line_plot_data(bd,library,metric)
    #If there is no fuzzer as argument we compute the plot for every fuzzer
    if not fuzzers :
        fuzzers = df.index.values.tolist()
    fig, ax = plt.subplots(nrows=1,ncols=len(fuzzers), figsize=(10, 5))

    for fuzzer in fuzzers:
        i = fuzzers.index(fuzzer)
        figx = i
        #Currently the plot only expand in a row
        if(len(fuzzers) == 1) :
            axes = ax
        else :
            axes = ax[figx]

        x = np.array(df['x'][fuzzer])
        y = np.array(df['y'][fuzzer])
        ci = np.array(df['ci'][fuzzer])

        # axes.set_xscale('log')
        axes.step(x, y)
        axes.fill_between(x, (y - ci), (y + ci), color='b', alpha=.1)

        axes.set_title(fuzzer)
        axes.set_ylim((0, y_max + 5))
        axes.set_xlim((x_min, x_max + 5))
    plt.tight_layout(pad=2.0)
    fig.savefig('output/data/lineplot.svg', bbox_inches=matplotlib.transforms.Bbox.from_bounds(0, 0, 13, 10))
    plt.close()

def bug_survival_plots(bd):
    """
    { TODO document this function }

    :param bd: { A BenchmarkData object loaded from experiment summary file }
    :type  bd: { BenchmarkData }
    """

    FUZZERS = bd.get_all_fuzzers()
    METRICS = bd.get_all_metrics()
    MARKERS = ('.', '>')
    LINESTYLES = (':', '-')
    COLORS = tuple(c['color'] for c in
                   plt.rcParams['axes.prop_cycle'][:len(FUZZERS)])

    metric_markers = dict(zip(METRICS, MARKERS))
    metric_linestyles = dict(zip(METRICS, LINESTYLES))
    fuzzer_colors = dict(zip(FUZZERS, COLORS))

    def plot_target_program_bug(series):
        fig, ax = plt.subplots(figsize=(10,6))
        for ((fuzzer, metric), kmf) in series.items():
            kmf.plot(
                ax=ax, ci_show=True, legend=False,
                marker=metric_markers[metric],
                linestyle=metric_linestyles[metric],
                color=fuzzer_colors[fuzzer]
            )

        xticks = list_ticks(bd.get_campaign_duration())
        xticklables = list(map(lambda x: pp_time(x), xticks))
        ax.set_xscale('symlog')
        ax.set_xticks(xticks, minor=False)
        ax.set_xticklabels(xticklables)
        ax.set_xlim(left=10, right=bd.get_campaign_duration())
        ax.set_xlabel("Time")

        ax.set_ylim(bottom=0)
        ax.set_ymargin(0.1)
        ax.set_ylabel("Survival Probability")

        library, program, bug = series.name
        name = f'survival_{library}_{program}_{bug}.svg'
        fig.savefig(os.path.join('output', 'data', name), bbox_inches='tight')
        plt.close(fig)

    kmf, means = DataProcessing.bug_survival_data(bd)
    kmf.apply(plot_target_program_bug, axis=1)

    fig_legend = plt.figure()
    legend_lines = [Line2D([0], [0], label=fuzzer, color=fuzzer_colors[fuzzer])
                    for fuzzer in FUZZERS]
    fig_legend.legend(handles=legend_lines, loc='center', ncol=3)
    fig_legend.savefig(os.path.join('output', 'data', 'survival_legend.svg'),
                       bbox_inches='tight')

    # TODO plot means table as well


######################
## Helper functions ##
######################

def heatmap_plot(p_values, axes=None, symmetric=False, **kwargs):
    """
    Heatmap for p_values
    """

    if symmetric:
        mask = np.zeros_like(p_values)
        mask[np.triu_indices_from(p_values)] = True
    heatmap_args = {
        'linewidths': 0.5,
        'linecolor': '0.5',
        'clip_on': False,
        'square': True,
        'cbar_ax_bbox': [0.85, 0.35, 0.04, 0.3],
        'mask': mask if symmetric else None,
    }
    heatmap_args.update(kwargs)
    return sp.sign_plot(p_values, ax=axes, **heatmap_args)

def list_ticks(bound):
    DENOMINATIONS = [
        1 * 60, # minutes
        15 * 60, # quarter-hour
        30 * 60, # half-hour
        60 * 60, # hour
        12 * 60 * 60, # half-day
        24 * 60 * 60, # day
        7 * 24 * 60 * 60, # week
        30 * 24 * 60 * 60, # month
    ]
    current_denom = 0
    last_tick = min(DENOMINATIONS[current_denom], bound)
    ticks = [last_tick]
    while last_tick < bound:
        last_tick *= 2
        if (current_denom + 1) < len(DENOMINATIONS) \
            and last_tick >= DENOMINATIONS[current_denom + 1]:
            current_denom += 1
            last_tick = DENOMINATIONS[current_denom]
        ticks.append(last_tick)
    return ticks

def pp_time(time):
    if np.isnan(time) :
        return time
    if time < 60:
        return '%.fs' % time
    if time < (60 * 60):
        return '%.fm' % (time // 60)
    if time < (24 * 60 * 60):
        return '%.fh' % (time // (60 * 60))
    if time < (7 * 24 * 60 * 60):
        return '%.fd' % (time // (24 * 60 * 60))
    if time < (30 * 24 * 60 * 60):
        return '%.fw' % (time // (7 * 24 * 60 * 60))
    return '%.fM' % (time // (30 * 24 * 60 * 60))
