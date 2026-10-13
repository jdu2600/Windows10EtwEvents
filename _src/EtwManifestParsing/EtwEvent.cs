namespace EtwManifestParsing {
	public sealed class EtwEvent {
		public int Value { get; internal set; }
		public string Symbol { get; internal set; }
		public int Version { get; internal set; }
		public string Opcode { get; internal set; }
		public string Level { get; internal set; }
		public string Template { get; internal set; }
		public string Keyword { get; internal set; }
		public string Task { get; internal set; }

		// The id the Event Log API knows the event by: the full 32-bit message id of a
		// win:EventlogClassic event, otherwise the event id.
		public uint EventLogId { get; internal set; }

		public override string ToString() => $"{Symbol}={Value} {Opcode} {Template}";
	}
}
