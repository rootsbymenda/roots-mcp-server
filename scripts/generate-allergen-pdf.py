"""
Generate the 82 EU Allergen Cheat Sheet PDF - Two Halves branded.
Professional, clean, high-value giveaway for LinkedIn lead gen.
"""
import json
from fpdf import FPDF

with open('C:/BENDA_PROJECT/roots-mcp-server/scripts/allergens_full.json', 'r', encoding='utf-8') as f:
    allergens = json.load(f)

# Sort: original_26 first, then new_56
original = sorted([a for a in allergens if a['category'] == 'original_26'], key=lambda x: x['inci_name'] or x['chemical_name'])
new = sorted([a for a in allergens if a['category'] == 'new_56'], key=lambda x: x['inci_name'] or x['chemical_name'])


class AllergenPDF(FPDF):
    def header(self):
        if self.page_no() == 1:
            return  # custom cover, skip header on page 1
        self.set_font('Helvetica', 'B', 9)
        self.set_text_color(100, 100, 100)
        self.cell(0, 8, 'EU 82 Allergen Cheat Sheet  |  Two Halves Regulatory Intelligence', align='C')
        self.ln(10)
        self.set_draw_color(218, 165, 32)
        self.set_line_width(0.5)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(3)

    def footer(self):
        self.set_y(-15)
        self.set_font('Helvetica', 'I', 8)
        self.set_text_color(130, 130, 130)
        self.cell(0, 10, f'twohalves.ai  |  Page {self.page_no()}/{{nb}}', align='C')


pdf = AllergenPDF('P', 'mm', 'A4')
pdf.alias_nb_pages()
pdf.set_auto_page_break(auto=True, margin=20)

# ============ COVER PAGE ============
pdf.add_page()

# Gold accent bar at top
pdf.set_fill_color(218, 165, 32)
pdf.rect(0, 0, 210, 6, 'F')

# Title block
pdf.ln(30)
pdf.set_font('Helvetica', 'B', 32)
pdf.set_text_color(30, 30, 30)
pdf.cell(0, 15, 'EU 82 ALLERGEN', align='C')
pdf.ln(15)
pdf.cell(0, 15, 'CHEAT SHEET', align='C')

# Subtitle
pdf.ln(20)
pdf.set_font('Helvetica', '', 14)
pdf.set_text_color(80, 80, 80)
pdf.cell(0, 8, 'Complete Reference Guide for Cosmetic Formulators', align='C')
pdf.ln(8)
pdf.cell(0, 8, 'EU Regulation 2023/1545  |  Effective July 2026', align='C')

# Stats box
pdf.ln(20)
pdf.set_fill_color(245, 245, 245)
pdf.set_draw_color(218, 165, 32)
pdf.set_line_width(0.3)
pdf.rect(30, pdf.get_y(), 150, 40, 'DF')

pdf.set_font('Helvetica', 'B', 28)
pdf.set_text_color(218, 165, 32)
pdf.ln(5)
pdf.cell(0, 14, '26 + 56 = 82', align='C')
pdf.ln(12)
pdf.set_font('Helvetica', '', 11)
pdf.set_text_color(60, 60, 60)
pdf.cell(0, 8, '26 Original (Annex III)  +  56 New Additions  =  82 Total Allergens', align='C')

# Deadline callout
pdf.ln(25)
pdf.set_fill_color(180, 30, 30)
pdf.rect(30, pdf.get_y(), 150, 18, 'F')
pdf.set_font('Helvetica', 'B', 13)
pdf.set_text_color(255, 255, 255)
pdf.ln(4)
pdf.cell(0, 10, 'COMPLIANCE DEADLINE:  JULY 31, 2026', align='C')

# Branding
pdf.ln(30)
pdf.set_font('Helvetica', 'B', 16)
pdf.set_text_color(218, 165, 32)
pdf.cell(0, 10, 'TWO HALVES', align='C')
pdf.ln(8)
pdf.set_font('Helvetica', '', 10)
pdf.set_text_color(100, 100, 100)
pdf.cell(0, 6, 'Regulatory Intelligence for Cosmetics', align='C')
pdf.ln(6)
pdf.cell(0, 6, 'twohalves.ai  |  newsletter.twohalves.ai', align='C')


# ============ TABLE HELPER ============
def draw_table(pdf, title, subtitle, data, start_num=1):
    pdf.add_page()
    pdf.set_font('Helvetica', 'B', 16)
    pdf.set_text_color(30, 30, 30)
    pdf.cell(0, 10, title, align='L')
    pdf.ln(8)
    pdf.set_font('Helvetica', '', 10)
    pdf.set_text_color(100, 100, 100)
    pdf.cell(0, 6, subtitle, align='L')
    pdf.ln(10)

    # Table header
    col_widths = [8, 52, 35, 25, 25, 25]  # #, Name, CAS, Cat, Leave-on, Rinse-off
    headers = ['#', 'Ingredient (INCI)', 'CAS Number', 'Category', 'Leave-on %', 'Rinse-off %']

    pdf.set_font('Helvetica', 'B', 8)
    pdf.set_fill_color(40, 40, 40)
    pdf.set_text_color(255, 255, 255)
    for i, h in enumerate(headers):
        pdf.cell(col_widths[i], 7, h, border=1, fill=True, align='C')
    pdf.ln()

    pdf.set_font('Helvetica', '', 7)
    row_num = start_num
    for idx, a in enumerate(data):
        # Alternate row colors
        if idx % 2 == 0:
            pdf.set_fill_color(255, 255, 255)
        else:
            pdf.set_fill_color(248, 248, 248)

        pdf.set_text_color(50, 50, 50)

        name = a.get('inci_name') or a.get('chemical_name', '')
        if len(name) > 30:
            name = name[:28] + '..'
        cas = (a.get('cas_numbers') or '').split('|')[0]
        cat = 'NEW' if a.get('category') == 'new_56' else 'Original'
        leave_on = a.get('leave_on_threshold_pct')
        rinse_off = a.get('rinse_off_threshold_pct')

        leave_str = f"{leave_on}%" if leave_on is not None else '-'
        rinse_str = f"{rinse_off}%" if rinse_off is not None else '-'

        # Color code NEW vs Original
        pdf.cell(col_widths[0], 6, str(row_num), border=1, fill=True, align='C')
        pdf.cell(col_widths[1], 6, name, border=1, fill=True, align='L')
        pdf.cell(col_widths[2], 6, cas, border=1, fill=True, align='C')

        if cat == 'NEW':
            pdf.set_text_color(180, 30, 30)
            pdf.set_font('Helvetica', 'B', 7)
        else:
            pdf.set_text_color(50, 120, 50)
            pdf.set_font('Helvetica', 'B', 7)
        pdf.cell(col_widths[3], 6, cat, border=1, fill=True, align='C')

        pdf.set_text_color(50, 50, 50)
        pdf.set_font('Helvetica', '', 7)
        pdf.cell(col_widths[4], 6, leave_str, border=1, fill=True, align='C')
        pdf.cell(col_widths[5], 6, rinse_str, border=1, fill=True, align='C')
        pdf.ln()
        row_num += 1

        # Check if we need a new page
        if pdf.get_y() > 265:
            pdf.add_page()
            pdf.set_font('Helvetica', 'B', 8)
            pdf.set_fill_color(40, 40, 40)
            pdf.set_text_color(255, 255, 255)
            for i, h in enumerate(headers):
                pdf.cell(col_widths[i], 7, h, border=1, fill=True, align='C')
            pdf.ln()
            pdf.set_font('Helvetica', '', 7)

    return row_num


# ============ ORIGINAL 26+1 ============
next_num = draw_table(
    pdf,
    'SECTION 1: Original 26 Allergens',
    'Already regulated under EU Cosmetics Regulation (EC) No 1223/2009, Annex III',
    original,
    start_num=1
)

# ============ NEW 56 ============
draw_table(
    pdf,
    'SECTION 2: 56 New Allergens (July 2026)',
    'Added by EU Regulation 2023/1545 - mandatory labeling from July 31, 2026',
    new,
    start_num=next_num
)

# ============ KEY THRESHOLDS PAGE ============
pdf.add_page()
pdf.set_font('Helvetica', 'B', 16)
pdf.set_text_color(30, 30, 30)
pdf.cell(0, 10, 'Quick Reference: Labeling Thresholds', align='L')
pdf.ln(12)

boxes = [
    ('Leave-on Products', '0.001%', '10 ppm', 'Creams, serums, lotions, sunscreens,\nmakeup, lip products, deodorants'),
    ('Rinse-off Products', '0.01%', '100 ppm', 'Shampoos, conditioners, body wash,\nhand soap, hair dye, masks'),
]

for title, pct, ppm, examples in boxes:
    pdf.set_fill_color(245, 245, 245)
    pdf.set_draw_color(218, 165, 32)
    pdf.set_line_width(0.4)
    y_start = pdf.get_y()
    pdf.rect(10, y_start, 190, 35, 'DF')

    pdf.set_font('Helvetica', 'B', 12)
    pdf.set_text_color(30, 30, 30)
    pdf.ln(3)
    pdf.cell(95, 8, f'  {title}', align='L')
    pdf.set_font('Helvetica', 'B', 20)
    pdf.set_text_color(218, 165, 32)
    pdf.cell(95, 8, f'{pct}  ({ppm})', align='R')
    pdf.ln(10)
    pdf.set_font('Helvetica', '', 9)
    pdf.set_text_color(80, 80, 80)
    pdf.multi_cell(180, 5, f'  {examples}', align='L')
    pdf.ln(8)

# What you need to know section
pdf.ln(5)
pdf.set_font('Helvetica', 'B', 14)
pdf.set_text_color(30, 30, 30)
pdf.cell(0, 10, 'What This Means For You', align='L')
pdf.ln(10)

bullets = [
    'All 82 allergens must be individually labeled if above threshold concentrations',
    'Natural extracts containing these allergens are NOT exempt - if the allergen is present, it must be declared',
    'Fragrance compounds are the largest group - review all fragrance blends with suppliers',
    'Products already on the market must be reformulated or relabeled before July 31, 2026',
    'Non-compliance risks: product recall, market withdrawal, regulatory penalties',
    'Third-country exporters to the EU must also comply - this affects global supply chains',
]

pdf.set_font('Helvetica', '', 10)
pdf.set_text_color(50, 50, 50)
for b in bullets:
    pdf.cell(5, 7, '', align='L')
    pdf.set_font('Helvetica', 'B', 10)
    pdf.set_text_color(218, 165, 32)
    pdf.cell(5, 7, '>', align='L')
    pdf.set_font('Helvetica', '', 10)
    pdf.set_text_color(50, 50, 50)
    pdf.cell(0, 7, f' {b}', align='L')
    pdf.ln(7)

# CTA
pdf.ln(15)
pdf.set_fill_color(218, 165, 32)
pdf.rect(25, pdf.get_y(), 160, 30, 'F')
pdf.set_font('Helvetica', 'B', 12)
pdf.set_text_color(255, 255, 255)
pdf.ln(5)
pdf.cell(0, 8, 'Stay Ahead of Regulatory Changes', align='C')
pdf.ln(8)
pdf.set_font('Helvetica', '', 10)
pdf.cell(0, 8, 'Subscribe to our weekly regulatory intelligence digest', align='C')
pdf.ln(8)
pdf.set_font('Helvetica', 'B', 11)
pdf.cell(0, 8, 'newsletter.twohalves.ai', align='C')

# Save
output_path = 'C:/BENDA_PROJECT/EU-82-Allergen-Cheat-Sheet-Two-Halves.pdf'
pdf.output(output_path)
print(f'PDF saved to {output_path}')
print(f'Pages: {pdf.page_no()}')
