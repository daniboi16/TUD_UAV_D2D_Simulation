import pandas as pd

def consolidate_and_average(baseline_csv, proposed_csv, output_excel):
    baseline_df = pd.read_csv(baseline_csv)
    proposed_df = pd.read_csv(proposed_csv)
    cols_to_drop = ['Run ID', 'Random Seed']

    def get_averaged_data(df, mode):
        filtered = df[df['Simulation Mode'] == mode].copy()
        filtered = filtered.drop(columns=[c for c in cols_to_drop if c in filtered.columns])
        averaged = filtered.groupby(['Simulation Mode', 'Number of UEs'], as_index=False).mean()
        return averaged
    # --- 1. Raw filtered data ---
    baseline_u2u = baseline_df[baseline_df['Simulation Mode'] == 'BASELINE_U2U']
    baseline_u2n = baseline_df[baseline_df['Simulation Mode'] == 'BASELINE_U2N']
    proposed_u2u = proposed_df[proposed_df['Simulation Mode'] == 'PROPOSED_U2U']
    proposed_u2n = proposed_df[proposed_df['Simulation Mode'] == 'PROPOSED_U2N']
    # --- 2. Averaged data ---
    avg_baseline_u2u = get_averaged_data(baseline_df, 'BASELINE_U2U')
    avg_baseline_u2n = get_averaged_data(baseline_df, 'BASELINE_U2N')
    avg_proposed_u2u = get_averaged_data(proposed_df, 'PROPOSED_U2U')
    avg_proposed_u2n = get_averaged_data(proposed_df, 'PROPOSED_U2N')
    # Write to Excel
    with pd.ExcelWriter(output_excel, engine='openpyxl') as writer:
        # --- Sheet 1: Raw U2U Results ---
        proposed_u2u.to_excel(writer, sheet_name='U2U_Results', index=False)
        baseline_u2u.to_excel(
            writer, sheet_name='U2U_Results', startrow=len(proposed_u2u) + 2, index=False, header=False
        )
        # --- Sheet 2: Raw U2N Results ---
        proposed_u2n.to_excel(writer, sheet_name='U2N_Results', index=False)
        baseline_u2n.to_excel(
            writer, sheet_name='U2N_Results', startrow=len(proposed_u2n) + 2, index=False, header=False
        )
        # --- Sheet 3: Averaged U2U Results ---
        avg_proposed_u2u.to_excel(writer, sheet_name='Averaged_U2U', index=False)
        avg_baseline_u2u.to_excel(
            writer, sheet_name='Averaged_U2U', startrow=len(avg_proposed_u2u) + 2, index=False, header=False
        )
        # --- Sheet 4: Averaged U2N Results ---
        avg_proposed_u2n.to_excel(writer, sheet_name='Averaged_U2N', index=False)
        avg_baseline_u2n.to_excel(
            writer, sheet_name='Averaged_U2N', startrow=len(avg_proposed_u2n) + 2, index=False, header=False
        )
    print(f"Successfully saved combined and averaged data to {output_excel}")

consolidate_and_average('baseline_results.csv', 'proposed_results.csv', 'combined_results_with_averages.xlsx')