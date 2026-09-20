const escape = (value) => String(value).replace(/\\/g, '\\\\').replace(/\n/g, '\\n').replace(/"/g, '\\"');
const labelText = (labels) => {
  const entries = Object.entries(labels);
  return entries.length ? `{${entries.map(([key, value]) => `${key}="${escape(value)}"`).join(',')}}` : '';
};
const keyOf = (labels) => JSON.stringify(Object.entries(labels));

export class Registry {
  constructor() { this.metrics = []; }

  counter(name, help) {
    const values = new Map();
    const metric = {
      name, help, type: 'counter',
      inc: (labels = {}, value = 1) => {
        const key = keyOf(labels);
        const entry = values.get(key) ?? { labels, value: 0 };
        entry.value += value;
        values.set(key, entry);
      },
      lines: () => [...values.values()].map((entry) => `${name}${labelText(entry.labels)} ${entry.value}`)
    };
    this.metrics.push(metric);
    return metric;
  }

  gauge(name, help, collect) {
    let current = 0;
    const metric = {
      name, help, type: 'gauge',
      set: (value) => { current = value; },
      lines: () => {
        const value = collect ? collect() : current;
        return Array.isArray(value) ? value.map(([labels, item]) => `${name}${labelText(labels)} ${item}`) : [`${name} ${value}`];
      }
    };
    this.metrics.push(metric);
    return metric;
  }

  histogram(name, help, buckets) {
    const series = new Map();
    const metric = {
      name, help, type: 'histogram',
      observe: (labels, value) => {
        const key = keyOf(labels);
        const entry = series.get(key) ?? { labels, counts: buckets.map(() => 0), sum: 0, count: 0 };
        buckets.forEach((bound, index) => { if (value <= bound) entry.counts[index]++; });
        entry.sum += value;
        entry.count++;
        series.set(key, entry);
      },
      lines: () => [...series.values()].flatMap((entry) => [
        ...buckets.map((bound, index) => `${name}_bucket${labelText({ ...entry.labels, le: bound })} ${entry.counts[index]}`),
        `${name}_bucket${labelText({ ...entry.labels, le: '+Inf' })} ${entry.count}`,
        `${name}_sum${labelText(entry.labels)} ${Number(entry.sum.toFixed(9))}`,
        `${name}_count${labelText(entry.labels)} ${entry.count}`
      ])
    };
    this.metrics.push(metric);
    return metric;
  }

  render() {
    const blocks = [];
    for (const metric of this.metrics) {
      let lines;
      // A gauge's collect() runs arbitrary caller code (e.g. reading a file for the audit-forward
      // lag gauge); one failing metric must never take down the whole /metrics response, so it is
      // simply omitted rather than aborting the render.
      try { lines = metric.lines(); } catch { continue; }
      blocks.push(`# HELP ${metric.name} ${metric.help}`, `# TYPE ${metric.name} ${metric.type}`, ...lines);
    }
    return `${blocks.join('\n')}\n`;
  }
}
