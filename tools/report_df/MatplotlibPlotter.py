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
from copy import deepcopy
import re

def expected_time_to_trigger(bd, outdir):
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
    annotations[fuzzer_label] = annotations[fuzzer_label].applymap(lambda x: pp_time(x))
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
    max_num_trials = bd.frame.reset_index().groupby('Fuzzer')['Campaign'] \
                       .nunique().max()
    xticks = list_ticks(bd.duration * max_num_trials)[4:]
    xticklables = list(map(lambda x: pp_time(x), xticks))

    cbar = ax.collections[0].colorbar
    cbar.set_ticks(xticks)
    cbar.set_ticklabels(xticklables)
    ax.patch.set(fill='True',color='darkgrey')
    ax.xaxis.tick_top()

    name, path = output(outdir, 'data', 'summary_expected_ttb_heat.svg')
    fig.savefig(path)
    plt.close()
    return path

def unique_bugs_per_target(bd, outdir, metric, libraries=None, symmetric=False, ncols=3):
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

    unique_bugs, _, p_values = DataProcessing.unique_bugs_per_target_data(bd, metric)

    #If there is no target as argument we compute the plot for every fuzzer
    all_libraries = bd.get_all_targets()
    if libraries :
        drop_libraries = set(all_libraries).difference(libraries)
        unique_bugs.drop(level='Target', labels=drop_libraries, inplace=True)
        p_values.drop(level='Target', labels=drop_libraries, inplace=True)
    else:
        libraries = all_libraries

    nrows = (len(libraries) - 1) // ncols + 1
    fig, axs = plt.subplots(nrows=nrows, ncols=ncols, figsize=(12, 12), squeeze=False)

    for target, ax in zip(libraries, axs.flat):
        lib_data = p_values.xs(target, level='Target', drop_level=True)
        # maintain symmetry by removing "extra" fuzzers
        lib_data = lib_data.transpose().reindex(lib_data.index)

        heatmap_plot(lib_data, symmetric=symmetric, axes=ax, labels=False, \
            cbar_ax_bbox=[1, 0.4, 0.02, 0.2])

        ax.set_title(target)
        # axes.get_yaxis().set_visible(False)

    for ax in axs.flat[len(libraries):]:
        fig.delaxes(ax)
    fig.tight_layout(pad=2.0)

    sigmatrix, path = output(outdir, 'plot', 'summary_signplot.svg')
    fig.savefig(path, bbox_inches='tight')

    fig, ax = plt.subplots(figsize=(12, 6))
    unique_bugs.groupby(['Fuzzer','Target']) \
               .mean().unstack(0) \
               .plot.bar(width=0.8,
                         ax=ax,
                         yerr=unique_bugs.groupby(['Fuzzer','Target']) \
                                         .std().unstack(0)
                )
    ax.legend(loc='upper left', bbox_to_anchor=(1,1))
    ax.set_ylabel("Bugs Triggered")
    ax.set_xlabel("Targets")
    ax.set_xticklabels(ax.get_xticklabels(), rotation=0)

    barplot, path = output(outdir, 'plot', 'summary_unique_bugs.svg')
    fig.savefig(path, bbox_inches='tight')
    plt.close()
    return barplot, sigmatrix

def bug_metric_boxplot(bd, outdir):
    """
    Create box plot graph showing the time distribution
    of bugs who satisfid the metric

    :param bd: { A BenchmarkData object loaded from experiment summary file }
    :type  bd: { BenchmarkData }

    :param fuzzer: { From which fuzzer }
    :type  fuzzer: { string }

    :param target: { From which target }
    :type  target: { string }

    :param metric: { chosen metric }
    :type  metric: { string }
    """

    def plot_boxes(df):
        fuzzer, target, program, metric = df.name
        df = df.unstack('BugID')
        df = df.droplevel(level=0, axis='columns')

        fig, ax = plt.subplots(figsize=(8,5))
        df.plot.box(ax=ax, vert=False)

        xticks = list_ticks(bd.duration)
        xticklables = list(map(lambda x: pp_time(x), xticks))
        ax.set_xscale('symlog')
        ax.set_xticks(xticks, minor=False)
        ax.set_xticklabels(xticklables)
        ax.set_xlim(left=5, right=bd.duration)
        ax.set_xlabel("Time")
        ax.set_ylabel("Bug ID")
        fig.suptitle(f'{metric}. Target: {target}. Program: {program}')

        name, path = output(outdir, 'plot', f'box_{fuzzer}_{target}_{program}_{metric}.svg')
        fig.savefig(path, bbox_inches='tight')
        plt.close(fig)
        return name

    df = bd.frame
    outfiles = df.groupby(['Fuzzer', 'Target', 'Program', 'Metric']) \
                 .apply(plot_boxes)

    return outfiles

def line_plot_unqiue_bugs(bd, outdir, fuzzers, target, metric) :
    """
    Creates a line plot for each fuzzer,target pair
    If fuzzers is empty then a plot for every known fuzzer will be computed

    :param bd: { A BenchmarkData object loaded from experiment summary file }
    :type  bd: { BenchmarkData }

    :param fuzzers: { list of fuzzer names }
    :type  fuzzers: { list }

    :param target: { target used to compute the line plots }
    :type  target: { string }

    :param metric: { chosen metric }
    :type  metric: { string }

    """

    # TODO something's broken here, fix it

    df, x_max, y_max, x_min = DataProcessing.line_plot_data(bd,target,metric)
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

    name, path = output(outdir, 'plot', 'lineplot.svg')
    fig.savefig(path, bbox_inches='tight')
    plt.close()
    return name

def bug_survival_plots(bd, outdir):
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

    kmf, means = DataProcessing.bug_survival_data(bd)

    ###
    # Plot means table
    ###

    # get the fuzzers with minimum and maximum metrics for every bug
    def generate_color_mask(df):
        def series_to_mask(series, df):
            idx = pd.MultiIndex.from_product([*series.index.levels, series.unique()])
            mask = series.reindex(idx, fill_value=False)
            mask = mask.unstack().apply(lambda x: x == x.name)
            return mask.reindex_like(df)

        uniq_min = df.stack(level=0).groupby(level=0) \
                        .apply(lambda x: x[x == x.min()].count() == 1).stack()
        uniq_max = df.stack(level=0).groupby(level=0) \
                        .apply(lambda x: x[x == x.max()].count() == 1).stack()

        # filter out entries which do not need to be highlighted
        mins = df.stack().groupby(level=0, as_index=False) \
                            .idxmin(axis=1).droplevel(0)
        mins = mins[uniq_min == True]
        maxs = df.stack().groupby(level=0, as_index=False) \
                            .idxmax(axis=1).droplevel(0)
        maxs = maxs[uniq_max == True]
        survivals = df == bd.duration

        color_df = series_to_mask(mins, df.stack()).unstack() \
                    .applymap(lambda x: 'background-color: #bfe8c2' if x else None)
        color_df.update(series_to_mask(maxs, df.stack()).unstack() \
                    .applymap(lambda x: 'background-color: #e2ea67' if x else None))
        color_df.update(survivals \
                    .applymap(lambda x: 'background-color: #efa2a2' if x else None))
        color_df.fillna('', inplace=True)
        color_df = color_df.reindex_like(df)
        return color_df

    # adjust dataframe for better presentation
    means = means.droplevel('Target')

    agg = means.stack(0).groupby('BugID') \
                        .apply(lambda x: pd.Series(
                            {
                                Metric.REACHED.value:   x[Metric.REACHED.value].mean(),
                                Metric.TRIGGERED.value: x[Metric.TRIGGERED.value].mean()
                            }
                        ))
    agg.columns = pd.MultiIndex.from_product([['Aggregate'], [Metric.REACHED.value, Metric.TRIGGERED.value]])
    means = means.join(agg)

    means = means.stack() \
                 .sort_values(
                    by='Fuzzer',
                    ascending=False,
                    axis='columns',
                    key=lambda idx: [means[(f, Metric.TRIGGERED.value)][means[(f, Metric.TRIGGERED.value)] < bd.duration].count() for f in idx]) \
                 .unstack()
    means.sort_values(by=('Aggregate', Metric.TRIGGERED.value), inplace=True)

    means.drop(columns='Aggregate', level=0, inplace=True)
    means.rename(columns={Metric.REACHED.value: 'R', Metric.TRIGGERED.value: 'T'}, inplace=True)
    means.rename_axis(index='Bug ID', inplace=True)

    styler = means.style
    # apply whole-table styling
    styler.set_table_styles([
        {
            # rows have alternating colors
            'selector': 'tr:nth-child(even)',
            'props':    [('background-color', '#ececec')]
        },
        {
            # hovered-over rows are highlighted
            'selector': 'tbody tr:hover',
            'props':    [('background-color', '#d9edfd')]
        },
        {
            # hide column names
            'selector': 'thead tr:not(:last-child) .index_name',
            'props':    [('visibility', 'hidden')]
        },
        {
            'selector': 'thead tr:nth-child(3)',
            'props':    [('display', 'none')]
        },
        {
            # right-align table data cells
            'selector': 'tbody td',
            'props':    [('padding', '2px 5px 2px 15px'), ('text-align', 'right')]
        },
        {
            # center-align table header cells
            'selector': 'th',
            'props':    [('padding', '2px 5px 2px 5px'), ('text-align', 'center')]
        },
        {
            # remove horizontal borders
            'selector': 'th, td, tr',
            'props':    [('border-top', 'none'), ('border-bottom', 'none'), ('border-radius', '0px')]
        },
        {
            # add vertical borders
            'selector': 'thead tr:first-child th:not(:last-child), th:nth-child(odd):not(:last-child), td:nth-child(odd):not(:last-child)',
            'props':    [('border-right', '1px solid #888888')]
        },
        {
            # make borders connect
            'selector': '',
            'props':    [('border-collapse', 'collapse')]
        }
    ])
    styler.set_uuid('survival_table')
    # format entries to be human-readable
    styler.format(pp_time)

    # apply best/worst performance highlights
    hiliter = deepcopy(styler)
    hiliter.apply(axis=None, func=generate_color_mask)

    # apply heatmap
    cm = sns.color_palette("vlag", as_cmap=True)
    heatmap = deepcopy(styler)
    heatmap.background_gradient(cmap=cm, low=.3, high=.3,
                                         vmin=0, vmax=bd.duration)

    template = styler.env.get_template("html.tpl")
    style_tpl = styler.env.from_string(
        source=r'{% extends "html.tpl" %}{% block table %}{% endblock %}'
    )
    table_tpl = styler.env.from_string(
        source=r'{% extends "html.tpl" %}{% block style %}{% endblock %}'
    )

    styler.template = table_tpl
    hiliter.template = style_tpl
    heatmap.template = style_tpl

    table_html = re.sub(r'colspan=(\d+)', r'colspan="\1"', styler.render())
    table_name, path = output(outdir, 'data', 'mean_survival.html')
    with open(path, 'w') as f:
        f.write(table_html)

    hiliter_css = '\n'.join(hiliter.render().split('\n')[1:-1]) + '}'
    hiliter_name, path = output(outdir, 'css', 'survival_hiliter.css')
    with open(path, 'w') as f:
        f.write(hiliter_css)

    heatmap_css = '\n'.join(heatmap.render().split('\n')[1:-1]) + '}'
    heatmap_name, path = output(outdir, 'css', 'survival_heatmap.css')
    with open(path, 'w') as f:
        f.write(heatmap_css)

    ###
    # Plot bug survival timelines
    ###
    def plot_target_program_bug(series):
        fig, ax = plt.subplots(figsize=(10,6))
        for ((fuzzer, metric), kmf) in series.items():
            kmf.plot(
                ax=ax, ci_show=True, legend=False,
                marker=metric_markers[metric],
                linestyle=metric_linestyles[metric],
                color=fuzzer_colors[fuzzer]
            )

        xticks = list_ticks(bd.duration)
        xticklables = list(map(lambda x: pp_time(x), xticks))
        ax.set_xscale('symlog')
        ax.set_xticks(xticks, minor=False)
        ax.set_xticklabels(xticklables)
        ax.set_xlim(left=10, right=bd.duration)
        ax.set_xlabel("Time")

        ax.set_ylim(bottom=0)
        ax.set_ymargin(0.1)
        ax.set_ylabel("Survival Probability")

        target, program, bug = series.name
        name, path = output(outdir, 'plot', f'survival_{target}_{program}_{bug}.svg')

        fig.savefig(path, bbox_inches='tight')
        plt.close(fig)
        return name

    outfiles = kmf.apply(plot_target_program_bug, axis=1)

    fig_legend = plt.figure()
    legend_lines = [Line2D([0], [0], label=fuzzer, color=fuzzer_colors[fuzzer])
                    for fuzzer in FUZZERS]
    fig_legend.legend(handles=legend_lines, loc='center', ncol=3)

    outlegend, path = output(outdir, 'plot', 'survival_legend.svg')
    fig_legend.savefig(path, bbox_inches='tight')

    return outfiles, outlegend, table_name, hiliter_name, heatmap_name

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

def output(outdir, klass, label):
    name = os.path.join(klass, label)
    path = os.path.join(outdir, name)
    return name, path