import jinja2
import MatplotlibPlotter
from Metric import Metric
import os
import errno

def generate_main_page(bd, base, env, **kwargs):
    def pp_time(time):
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

    template = env.get_template('main_template.md')

    parameters = {
        'duration': pp_time(bd.duration),
        'trials': bd.trials,
        'version': bd.version,
        'target_list': bd.get_all_targets(),
        'fuzzer_list': bd.get_all_fuzzers()
    }
    parameters.update(kwargs)

    html = template.render(base_template=base, **parameters)
    return html

def generate_target_page(bd, base, env, target, **kwargs):
    template = env.get_template('target_template.md')
    html = template.render(base_template=base, target=target, **kwargs)
    return html

def generate_fuzzer_page(bd, base, env, fuzzer, **kwargs):
    template = env.get_template('fuzzer_template.md')
    html = template.render(base_template=base, fuzzer=fuzzer, **kwargs)
    return html

def generate_report(bd, outdir, report_title="Report", **kwargs):
    def ensure_dir(path):
        try:
            os.makedirs(path)
        except OSError as e:
            if e.errno != errno.EEXIST:
                raise

    ensure_dir(os.path.join(outdir, 'css'))
    ensure_dir(os.path.join(outdir, 'data'))
    ensure_dir(os.path.join(outdir, 'plot'))
    ensure_dir(os.path.join(outdir, 'fuzzers'))
    ensure_dir(os.path.join(outdir, 'targets'))

    boxplots = MatplotlibPlotter.bug_metric_boxplot(bd, outdir)
    uniq_bugs, sigmatrix = MatplotlibPlotter.unique_bugs_per_target(bd, outdir, Metric.TRIGGERED.value)
    ett = MatplotlibPlotter.expected_time_to_trigger(bd, outdir)
    survplots, survlegend, survtable, hiliter_css, heatmap_css = MatplotlibPlotter.bug_survival_plots(bd, outdir)
    ppool = locals()

    env = jinja2.Environment(loader=jinja2.ChoiceLoader(
                                        [jinja2.FileSystemLoader('templates'),
                                         jinja2.FileSystemLoader(outdir)])
                            )
    base_template = env.get_template('base.md')

    main = generate_main_page(bd, base_template, env,
        **{k: ppool[k] for k in
            ppool.keys() & {
                              'uniq_bugs', 'sigmatrix', 'ett',
                              'survtable', 'hiliter_css', 'heatmap_css',
                              'report_title'
                           }
        }
    )

    fuzzers = {}
    for fuzzer in bd.get_all_fuzzers():
        fuzzers[fuzzer] = generate_fuzzer_page(bd, base_template, env, fuzzer,
                                               plots=boxplots.xs(fuzzer))

    targets = {}
    for target in bd.get_all_targets():
        targets[target] = generate_target_page(bd, base_template, env, target,
                                               plots=survplots.xs(target),
                                               legend=survlegend)

    with open(os.path.join(outdir, 'index.md'), 'w') as f:
        f.write(main)

    for fuzzer, html in fuzzers.items():
        with open(os.path.join(outdir, 'fuzzers', f'{fuzzer}.md'), 'w') as f:
            f.write(html)

    for target, html in targets.items():
        with open(os.path.join(outdir, 'targets', f'{target}.md'), 'w') as f:
            f.write(html)