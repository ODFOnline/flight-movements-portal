export type ParsedItinerary = {
  traveler: string;
  pnr?: string;
  segments: Array<{
    carrier: string;
    flightNum: string;
    departIATA: string;
    departName: string;
    departDT: string;
    arriveIATA: string;
    arriveName: string;
    arriveDT: string;
    equipment?: string;
  }>;
};