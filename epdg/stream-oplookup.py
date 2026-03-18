#!/usr/bin/env python3
"""
3GPP Public Domain Discovery — Streamlit Dashboard
Explore and analyse discovered DNS records from the database.
"""

import sqlite3
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

DB_PATH = Path(__file__).parent / "database.db"

SERVICE_COLORS = {
    "epdg.epc": "#1f77b4",
    "ims":      "#ff7f0e",
    "bsf":      "#2ca02c",
    "xcap.ims": "#d62728",
    "gan":      "#9467bd",
}

st.set_page_config(
    page_title="3GPP Public Domain Explorer",
    page_icon="📡",
    layout="wide",
)


@st.cache_resource
def get_conn():
    if not DB_PATH.exists():
        st.error(f"Database not found at {DB_PATH}. Run 3gpppub-dns-database-population.py first.")
        st.stop()
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


@st.cache_data(ttl=300)
def load_fqdns() -> pd.DataFrame:
    conn = get_conn()
    df = pd.read_sql_query(
        """
        SELECT f.mnc, f.mcc, f.operator, f.country_name,
               f.fqdn, f.record_type, f.resolved_ips,
               f.first_seen, f.last_seen,
               CASE
                 WHEN f.fqdn LIKE 'epdg.epc%' THEN 'epdg.epc'
                 WHEN f.fqdn LIKE 'xcap.ims%' THEN 'xcap.ims'
                 WHEN f.fqdn LIKE 'ims%'      THEN 'ims'
                 WHEN f.fqdn LIKE 'bsf%'      THEN 'bsf'
                 WHEN f.fqdn LIKE 'gan%'      THEN 'gan'
                 ELSE 'other'
               END AS service
        FROM available_fqdns f
        ORDER BY f.country_name, f.operator
        """,
        conn,
    )
    return df


@st.cache_data(ttl=300)
def load_operators() -> pd.DataFrame:
    conn = get_conn()
    return pd.read_sql_query(
        "SELECT mnc, mcc, operator, country_name, country_code, last_scanned FROM operators ORDER BY country_name",
        conn,
    )


def service_label(fqdn: str) -> str:
    for svc in ("epdg.epc", "xcap.ims", "ims", "bsf", "gan"):
        if fqdn.startswith(svc):
            return svc
    return "other"


# ── Sidebar filters ────────────────────────────────────────────────────────────

st.sidebar.title("🔍 Filters")

df_all = load_fqdns()
df_ops = load_operators()

countries = sorted(df_all["country_name"].dropna().unique())
services  = sorted(df_all["service"].unique())
rtypes    = sorted(df_all["record_type"].unique())

sel_countries = st.sidebar.multiselect("Country", countries, placeholder="All countries")
sel_services  = st.sidebar.multiselect("Service", services, placeholder="All services")
sel_rtypes    = st.sidebar.multiselect("Record type", rtypes, default=["A"], placeholder="A + AAAA")

operator_search = st.sidebar.text_input("Operator name contains", "")

# Apply filters
df = df_all.copy()
if sel_countries:
    df = df[df["country_name"].isin(sel_countries)]
if sel_services:
    df = df[df["service"].isin(sel_services)]
if sel_rtypes:
    df = df[df["record_type"].isin(sel_rtypes)]
if operator_search:
    df = df[df["operator"].str.contains(operator_search, case=False, na=False)]

# ── Header ─────────────────────────────────────────────────────────────────────

st.title("📡 3GPP Public Domain Explorer")
st.caption(
    "Discovered DNS records in `pub.3gppnetwork.org` — "
    "services: ims · epdg.epc · bsf · gan · xcap.ims"
)

# ── Top metrics ────────────────────────────────────────────────────────────────

c1, c2, c3, c4, c5 = st.columns(5)
c1.metric("Total FQDNs",    len(df))
c2.metric("Countries",      df["country_name"].nunique())
c3.metric("Operators",      df[["mnc","mcc"]].drop_duplicates().shape[0])
c4.metric("ePDG endpoints", len(df[df["service"] == "epdg.epc"]))
c5.metric("IMS endpoints",  len(df[df["service"] == "ims"]))

st.divider()

# ── Tabs ───────────────────────────────────────────────────────────────────────

tab_country, tab_service, tab_operator, tab_raw, tab_map, tab_score, tab_asn = st.tabs(
    ["🌍 Country Stats", "📊 Service Breakdown", "🏢 Operator Lookup",
     "📋 Raw Data", "🗺️ Map", "🏆 Capability Score", "🌐 ASN / Hosting"]
)

# ── Country Stats ──────────────────────────────────────────────────────────────

with tab_country:
    st.subheader("Services discovered per country")

    country_stats = (
        df.groupby(["country_name", "service"])
        .size()
        .reset_index(name="count")
    )
    country_total = (
        df.groupby("country_name")
        .agg(
            total_fqdns=("fqdn", "count"),
            operators=("mcc", lambda x: df.loc[x.index, ["mnc","mcc"]].drop_duplicates().shape[0]),
            services_present=("service", lambda x: ", ".join(sorted(x.unique()))),
        )
        .reset_index()
        .sort_values("total_fqdns", ascending=False)
    )

    top_n = st.slider("Show top N countries", 5, 50, 20, key="top_n_country")

    top_countries = country_total.head(top_n)["country_name"].tolist()
    plot_data = country_stats[country_stats["country_name"].isin(top_countries)]

    fig_bar = px.bar(
        plot_data,
        x="country_name",
        y="count",
        color="service",
        color_discrete_map=SERVICE_COLORS,
        title=f"Top {top_n} countries — FQDNs by service type",
        labels={"country_name": "Country", "count": "FQDNs", "service": "Service"},
        height=450,
    )
    fig_bar.update_layout(xaxis_tickangle=-45, legend_title="Service")
    st.plotly_chart(fig_bar, use_container_width=True)

    st.dataframe(
        country_total.rename(columns={
            "country_name": "Country",
            "total_fqdns": "Total FQDNs",
            "operators": "Operators",
            "services_present": "Services Present",
        }),
        use_container_width=True,
        hide_index=True,
    )

# ── Service Breakdown ──────────────────────────────────────────────────────────

with tab_service:
    st.subheader("Global service distribution")

    col_pie, col_trend = st.columns(2)

    with col_pie:
        svc_counts = df.groupby("service").size().reset_index(name="count")
        fig_pie = px.pie(
            svc_counts,
            names="service",
            values="count",
            color="service",
            color_discrete_map=SERVICE_COLORS,
            title="FQDNs by service type",
        )
        st.plotly_chart(fig_pie, use_container_width=True)

    with col_trend:
        rtype_counts = df.groupby(["service", "record_type"]).size().reset_index(name="count")
        fig_rtype = px.bar(
            rtype_counts,
            x="service",
            y="count",
            color="record_type",
            barmode="group",
            title="A vs AAAA records per service",
            labels={"service": "Service", "count": "Count", "record_type": "Record Type"},
        )
        st.plotly_chart(fig_rtype, use_container_width=True)

    st.subheader("Service coverage heatmap (top countries)")
    pivot = (
        df.groupby(["country_name", "service"])
        .size()
        .unstack(fill_value=0)
        .reset_index()
    )
    top_heat = country_total.head(30)["country_name"].tolist()
    pivot_top = pivot[pivot["country_name"].isin(top_heat)].set_index("country_name")

    fig_heat = px.imshow(
        pivot_top,
        color_continuous_scale="Blues",
        title="Service count heatmap — top 30 countries",
        labels={"color": "FQDNs"},
        aspect="auto",
        height=600,
    )
    st.plotly_chart(fig_heat, use_container_width=True)

# ── Operator Lookup ────────────────────────────────────────────────────────────

with tab_operator:
    st.subheader("Look up a specific operator")

    col_mcc, col_mnc = st.columns(2)
    with col_mcc:
        mcc_options = sorted(df["mcc"].unique())
        sel_mcc = st.selectbox("MCC", mcc_options, format_func=lambda v: f"{v}")
    with col_mnc:
        mnc_options = sorted(df[df["mcc"] == sel_mcc]["mnc"].unique())
        sel_mnc = st.selectbox("MNC", mnc_options, format_func=lambda v: f"{v:03d}")

    op_rows = df[(df["mcc"] == sel_mcc) & (df["mnc"] == sel_mnc)]

    if not op_rows.empty:
        info = op_rows.iloc[0]
        st.markdown(f"**Operator:** {info['operator']}  \n**Country:** {info['country_name']}")
        st.markdown(f"**MCC:** `{sel_mcc}` | **MNC:** `{sel_mnc:03d}`")

        for svc in op_rows["service"].unique():
            svc_df = op_rows[op_rows["service"] == svc][["fqdn", "record_type", "resolved_ips"]]
            with st.expander(f"🔹 {svc} ({len(svc_df)} record(s))", expanded=True):
                st.dataframe(svc_df, use_container_width=True, hide_index=True)
    else:
        st.info("No records found for this MCC/MNC combination.")

# ── Raw Data ───────────────────────────────────────────────────────────────────

with tab_raw:
    st.subheader("All discovered FQDNs")
    st.caption(f"{len(df)} records matching current filters")

    display_cols = ["country_name", "operator", "mcc", "mnc", "service",
                    "fqdn", "record_type", "resolved_ips", "last_seen"]
    st.dataframe(
        df[display_cols].rename(columns={
            "country_name": "Country",
            "operator":     "Operator",
            "mcc":          "MCC",
            "mnc":          "MNC",
            "service":      "Service",
            "fqdn":         "FQDN",
            "record_type":  "Type",
            "resolved_ips": "Resolved IPs",
            "last_seen":    "Last Seen",
        }),
        use_container_width=True,
        hide_index=True,
        height=500,
    )

    csv = df[display_cols].to_csv(index=False).encode()
    st.download_button(
        "⬇️ Download CSV",
        data=csv,
        file_name="3gpp_fqdns.csv",
        mime="text/csv",
    )

# ── Map ─────────────────────────────────────────────────────────────────────────

with tab_map:
    st.subheader("Geographic distribution of discovered services")

    # Build country-level aggregate with ISO alpha-3 from operators table
    map_df = (
        df.groupby(["country_name"])
        .agg(total_fqdns=("fqdn", "count"), operators=("mcc", "nunique"))
        .reset_index()
    )
    # Attach country_code from operators table for choropleth
    code_map = (
        df_ops[["country_name", "country_code"]]
        .dropna(subset=["country_code"])
        .drop_duplicates("country_name")
    )
    map_df = map_df.merge(code_map, on="country_name", how="left")

    if map_df["country_code"].notna().any():
        fig_map = px.choropleth(
            map_df.dropna(subset=["country_code"]),
            locations="country_code",
            color="total_fqdns",
            hover_name="country_name",
            hover_data={"operators": True, "total_fqdns": True, "country_code": False},
            color_continuous_scale="Viridis",
            title="3GPP public domain FQDNs discovered — by country",
            labels={"total_fqdns": "FQDNs", "country_code": ""},
        )
        fig_map.update_layout(height=550)
        st.plotly_chart(fig_map, use_container_width=True)
    else:
        st.info(
            "Country codes not available in the database. "
            "Re-run the scanner to populate country_code from the MCC/MNC list."
        )
        st.bar_chart(
            map_df.set_index("country_name")["total_fqdns"].sort_values(ascending=False).head(40)
        )

# ── Capability Score ──────────────────────────────────────────────────────────

with tab_score:
    st.subheader("Operator 3GPP Service Readiness Score")
    st.caption(
        "Scores each operator based on which public 3GPP services are published. "
        "Run `3gpppub-5g-discovery.py` to unlock 5G SA scoring."
    )

    SCORE_WEIGHTS = {
        "epdg.epc": ("VoWiFi (ePDG)",           25, "📶"),
        "ims":      ("VoLTE (IMS)",              20, "📞"),
        "xcap.ims": ("Device Mgmt (XCAP/IMS)",  15, "⚙️"),
        "bsf":      ("5G Auth (BSF)",            20, "🔐"),
        "gan":      ("UMA/GAN (WiFi Calling)",   10, "📡"),
    }

    # Per-operator service pivot
    score_pivot = (
        df_all.groupby(["mnc", "mcc", "operator", "country_name", "service"])
        .size()
        .reset_index(name="count")
        .pivot_table(
            index=["mnc", "mcc", "operator", "country_name"],
            columns="service",
            values="count",
            fill_value=0,
        )
        .reset_index()
    )

    # Check for 5G SA data
    conn_score = get_conn()
    has_5g_table = conn_score.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='fiveg_fqdns'"
    ).fetchone()

    if has_5g_table:
        fiveg_ops = set(
            conn_score.execute(
                "SELECT DISTINCT mcc || '-' || mnc FROM fiveg_fqdns"
            ).fetchall()
        )
        score_pivot["_5g_key"] = (
            score_pivot["mcc"].astype(str) + "-" + score_pivot["mnc"].astype(str)
        )
        score_pivot["5g_sa"] = score_pivot["_5g_key"].isin(
            {r[0] for r in fiveg_ops}
        ).astype(int)
    else:
        score_pivot["5g_sa"] = 0

    # Compute score
    def compute_score(row):
        score = 0
        breakdown = []
        for svc, (label, pts, icon) in SCORE_WEIGHTS.items():
            if svc in row and row[svc] > 0:
                score += pts
                breakdown.append(f"{icon} {label} +{pts}")
        if row.get("5g_sa", 0):
            score += 20
            breakdown.append("🚀 5G SA (NRF/SEPP) +20")
        return score, " | ".join(breakdown)

    score_pivot[["score", "capabilities"]] = score_pivot.apply(
        lambda r: pd.Series(compute_score(r)), axis=1
    )
    score_pivot = score_pivot.sort_values("score", ascending=False).reset_index(drop=True)
    score_pivot["rank"] = score_pivot.index + 1

    # Filter
    score_countries = sorted(score_pivot["country_name"].dropna().unique())
    sel_score_country = st.multiselect(
        "Filter by country", score_countries, placeholder="All countries", key="score_country"
    )
    min_score = st.slider("Minimum score", 0, 110, 0, key="min_score")

    filtered_scores = score_pivot.copy()
    if sel_score_country:
        filtered_scores = filtered_scores[filtered_scores["country_name"].isin(sel_score_country)]
    filtered_scores = filtered_scores[filtered_scores["score"] >= min_score]

    # Score distribution
    col_dist, col_medals = st.columns(2)
    with col_dist:
        score_bins = pd.cut(score_pivot["score"], bins=[0,20,40,60,80,100,110],
                            labels=["1-20","21-40","41-60","61-80","81-100","101+"])
        dist_df = score_bins.value_counts().sort_index().reset_index()
        dist_df.columns = ["Score range", "Operators"]
        fig_dist = px.bar(dist_df, x="Score range", y="Operators",
                          title="Score distribution across all operators",
                          color="Operators", color_continuous_scale="Viridis")
        st.plotly_chart(fig_dist, use_container_width=True)

    with col_medals:
        top10 = score_pivot.head(10)
        fig_top = px.bar(
            top10, x="score", y="operator", orientation="h",
            color="country_name", title="Top 10 operators by score",
            labels={"score": "Score", "operator": "Operator"},
            height=350,
        )
        fig_top.update_layout(yaxis={"categoryorder": "total ascending"})
        st.plotly_chart(fig_top, use_container_width=True)

    # Leaderboard table
    display_svc_cols = [c for c in ["epdg.epc","ims","xcap.ims","bsf","gan","5g_sa"]
                        if c in filtered_scores.columns]
    show_cols = ["rank", "country_name", "operator", "mcc", "mnc", "score", "capabilities"] + display_svc_cols

    st.dataframe(
        filtered_scores[show_cols].rename(columns={
            "rank": "#", "country_name": "Country", "operator": "Operator",
            "mcc": "MCC", "mnc": "MNC", "score": "Score",
            "capabilities": "Services", "epdg.epc": "ePDG",
            "ims": "IMS", "xcap.ims": "XCAP", "bsf": "BSF",
            "gan": "GAN", "5g_sa": "5G SA",
        }),
        use_container_width=True,
        hide_index=True,
        height=500,
    )

    # Score legend
    with st.expander("📖 Scoring guide"):
        st.markdown("| Service | Points | Meaning |")
        st.markdown("|---------|--------|---------|")
        for svc, (label, pts, icon) in SCORE_WEIGHTS.items():
            st.markdown(f"| {icon} {label} | **+{pts}** | `{svc}.*` record present |")
        st.markdown("| 🚀 5G SA | **+20** | NRF/SEPP found by `3gpppub-5g-discovery.py` |")
        st.markdown("\n**Max score: 110**")

# ── ASN / Hosting ─────────────────────────────────────────────────────────────

with tab_asn:
    st.subheader("ASN & Cloud Hosting Analysis")
    st.caption(
        "Run `3gpppub-asn-enricher.py` first to populate ASN data. "
        "Reveals whether operator infrastructure is on-premises or cloud-hosted."
    )

    conn_asn = get_conn()
    has_asn = "asn" in {
        row[1] for row in conn_asn.execute("PRAGMA table_info(available_fqdns)")
    }

    if not has_asn or not conn_asn.execute(
        "SELECT 1 FROM available_fqdns WHERE asn IS NOT NULL LIMIT 1"
    ).fetchone():
        st.info(
            "No ASN data found. Run `python3 3gpppub-asn-enricher.py` "
            "to enrich the database with BGP/ASN information."
        )
    else:
        asn_df = pd.read_sql_query(
            """
            SELECT operator, country_name, fqdn, record_type, resolved_ips,
                   asn, asn_org, hosting_provider, ip_country,
                   CASE
                     WHEN fqdn LIKE 'epdg.epc%' THEN 'epdg.epc'
                     WHEN fqdn LIKE 'xcap.ims%' THEN 'xcap.ims'
                     WHEN fqdn LIKE 'ims%'      THEN 'ims'
                     WHEN fqdn LIKE 'bsf%'      THEN 'bsf'
                     ELSE 'other'
                   END AS service
            FROM available_fqdns
            WHERE asn IS NOT NULL
            """,
            conn_asn,
        )

        col_p1, col_p2 = st.columns(2)

        with col_p1:
            prov_counts = asn_df["hosting_provider"].value_counts().reset_index()
            prov_counts.columns = ["provider", "count"]
            fig_prov = px.pie(
                prov_counts, names="provider", values="count",
                title="Infrastructure hosting providers",
                hole=0.4,
            )
            st.plotly_chart(fig_prov, use_container_width=True)

        with col_p2:
            cloud_svc = (
                asn_df.groupby(["hosting_provider", "service"])
                .size()
                .reset_index(name="count")
            )
            fig_cloud_svc = px.bar(
                cloud_svc, x="hosting_provider", y="count", color="service",
                title="Services per hosting provider",
                labels={"hosting_provider": "Provider", "count": "FQDNs"},
                color_discrete_map=SERVICE_COLORS,
            )
            fig_cloud_svc.update_layout(xaxis_tickangle=-35)
            st.plotly_chart(fig_cloud_svc, use_container_width=True)

        st.subheader("Cloud adoption by country")
        cloud_mask = ~asn_df["hosting_provider"].str.contains("On-premises", na=False)
        cloud_rate = (
            asn_df.groupby("country_name")
            .apply(lambda g: round(100 * g["hosting_provider"].str.contains("On-premises").eq(False).mean()))
            .reset_index(name="cloud_pct")
            .sort_values("cloud_pct", ascending=False)
            .head(30)
        )
        fig_cloud = px.bar(
            cloud_rate, x="country_name", y="cloud_pct",
            title="% of endpoints on public cloud (top 30 countries)",
            labels={"country_name": "Country", "cloud_pct": "Cloud %"},
            color="cloud_pct", color_continuous_scale="RdYlGn",
        )
        fig_cloud.update_layout(xaxis_tickangle=-45)
        st.plotly_chart(fig_cloud, use_container_width=True)

        st.subheader("Top ASNs")
        top_asns = (
            asn_df.groupby(["asn", "asn_org", "hosting_provider"])
            .agg(fqdns=("fqdn", "count"),
                 operators=("operator", "nunique"),
                 countries=("country_name", "nunique"))
            .reset_index()
            .sort_values("fqdns", ascending=False)
            .head(20)
        )
        st.dataframe(
            top_asns.rename(columns={
                "asn": "ASN", "asn_org": "Organisation",
                "hosting_provider": "Provider",
                "fqdns": "FQDNs", "operators": "Operators", "countries": "Countries",
            }),
            use_container_width=True,
            hide_index=True,
        )
