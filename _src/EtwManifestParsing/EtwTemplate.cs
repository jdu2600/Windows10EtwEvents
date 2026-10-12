namespace EtwManifestParsing {
	public sealed class EtwTemplateData {
		public string Name { get; set; }
		public string Type { get; set; }
	}

	public sealed class EtwTemplate {
		public string Id { get; }
		public EtwTemplateData[] Items { get; }

        internal EtwTemplate(string id, EtwTemplateData[] items)
        {
            Id = id;
            Items = items;
        }

        public override string ToString() => $"{Id} {Items.Length} template items";
	}
}
