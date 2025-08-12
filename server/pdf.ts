// Lazy-load pdf-parse to avoid its test-file read on startup
// and import the library implementation directly.
export async function extract(textBuffer: Buffer) {
  const { default: pdfParse } = await import('pdf-parse/lib/pdf-parse.js');
  const { text } = await pdfParse(textBuffer);
  return text.replace(/\r/g, '')
             .split('\n')
             .map(s => s.trim())
             .filter(Boolean);
}

export function parse(lines: string[]) {
  const out: any = { traveler: '', pnr: undefined, segments: [] as any[] };

  const travIdx = lines.findIndex(l => /^Traveler$/i.test(l));
  if (travIdx !== -1) out.traveler = lines[travIdx + 1]?.trim();

  const pnrIdx = lines.findIndex(l => /Travel Summary – Agency Record Locator/i.test(l));
  if (pnrIdx !== -1) {
    const m = lines[pnrIdx + 1]?.match(/([A-Z0-9]{6})/);
    if (m) out.pnr = m[1];
  }

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (/^AIR\s*-\s*/i.test(line)) {
      const prettyDateMatch = line.match(/AIR\s*-\s*\w+,\s*(\w+)\s*(\d{1,2})\s*(\d{4})/i);
      const prettyDate = prettyDateMatch ? `${prettyDateMatch[1]} ${prettyDateMatch[2]}, ${prettyDateMatch[3]}` : '';

      const carrierLine = lines[i + 1] || '';
      const mCF = carrierLine.match(/(.+?)\s+Flight\s+([A-Z]{2}\s*\d+)/i);
      const carrier = mCF?.[1]?.trim() || '';
      const flightNum = (mCF?.[2] || '').replace(/\s+/g, ' ');

      const depTag = lines[i + 2] || '';
      const depName = lines[i + 3] || '';
      const depTime = lines[i + 4] || '';

      const arrTag = lines[i + 5] || '';
      const arrName = lines[i + 6] || '';
      const arrTime = lines[i + 7] || '';

      const depIata = (depTag.match(/\((\w{3})\)/) || [])[1] || '';
      const arrIata = (arrTag.match(/\((\w{3})\)/) || [])[1] || '';

      function compose(dateStr: string, timeStr: string) {
        const t = timeStr.match(/(\d{1,2}:\d{2})\s*(AM|PM)/i);
        if (!dateStr || !t) return '';
        return new Date(`${dateStr} ${t[1]} ${t[2]}`).toISOString();
      }

      const departDT = compose(prettyDate, depTime);
      const arriveDT = compose(prettyDate, arrTime);

      out.segments.push({
        carrier, flightNum,
        departIATA: depIata, departName: depName, departDT,
        arriveIATA: arrIata, arriveName: arrName, arriveDT
      });
    }
  }
  return out;
}
