// SPDX-License-Identifier: MIT

#include "settings_page.hpp"

#include <QComboBox>
#include <QFormLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QIcon>
#include <QLabel>
#include <QPushButton>
#include <QScrollArea>
#include <QVariant>
#include <QVBoxLayout>

namespace finalis::wallet {
namespace {

void configure_page_layout(QVBoxLayout* layout, int spacing = 12) {
  if (!layout) return;
  layout->setContentsMargins(14, 14, 14, 14);
  layout->setSpacing(spacing);
}

void configure_form_layout(QFormLayout* layout) {
  if (!layout) return;
  layout->setContentsMargins(0, 0, 0, 0);
  layout->setHorizontalSpacing(14);
  layout->setVerticalSpacing(10);
  layout->setFieldGrowthPolicy(QFormLayout::ExpandingFieldsGrow);
  layout->setFormAlignment(Qt::AlignTop | Qt::AlignLeft);
  layout->setLabelAlignment(Qt::AlignLeft | Qt::AlignVCenter);
}

QLabel* make_brand_image(const QString& resource_path, const QSize& size, QWidget* parent, const QString& fallback = {}) {
  auto* label = new QLabel(parent);
  label->setAlignment(Qt::AlignCenter);
  QIcon icon(resource_path);
  const QPixmap pixmap = icon.pixmap(size);
  if (!pixmap.isNull()) {
    label->setPixmap(pixmap);
  } else {
    label->setText(fallback);
  }
  return label;
}

}  // namespace

SettingsPage::SettingsPage(QWidget* parent) : QWidget(parent) {
  auto* root = new QVBoxLayout(this);
  root->setContentsMargins(0, 0, 0, 0);

  auto* scroll = new QScrollArea(this);
  scroll->setWidgetResizable(true);
  scroll->setFrameShape(QFrame::NoFrame);
  auto* content = new QWidget(scroll);
  auto* layout = new QVBoxLayout(content);
  configure_page_layout(layout);

  auto* appearance_box = new QGroupBox("Appearance", this);
  auto* appearance_form = new QFormLayout(appearance_box);
  configure_form_layout(appearance_form);
  theme_combo_ = new QComboBox(appearance_box);
  theme_combo_->addItems({"Light", "Dark"});
  appearance_form->addRow("Theme", theme_combo_);
  layout->addWidget(appearance_box);

  auto* brand_box = new QGroupBox("Branding and About", this);
  auto* brand_layout = new QHBoxLayout(brand_box);
  branding_symbol_label_ = make_brand_image(":/branding/finalis-symbol.svg", QSize(52, 52), brand_box, "FLS");
  branding_symbol_label_->setMinimumSize(52, 52);
  branding_symbol_label_->setMaximumSize(52, 52);
  brand_layout->addWidget(branding_symbol_label_, 0, Qt::AlignTop);
  auto* brand_note_wrap = new QVBoxLayout();
  auto* brand_note = new QLabel(
      "Appearance and About remain top-level settings. Connection controls and diagnostics moved to Advanced.",
      brand_box);
  brand_note->setWordWrap(true);
  brand_note->setProperty("role", QVariant(QStringLiteral("muted")));
  about_button_ = new QPushButton("About", brand_box);
  brand_note_wrap->addWidget(brand_note);
  brand_note_wrap->addWidget(about_button_, 0, Qt::AlignLeft);
  brand_layout->addLayout(brand_note_wrap, 1);
  layout->addWidget(brand_box);

  auto* note = new QLabel(
      "This page now stays narrow: appearance, branding, and local app identity. "
      "Operational controls live under Advanced.",
      this);
  note->setWordWrap(true);
  note->setProperty("role", QVariant(QStringLiteral("muted")));
  layout->addWidget(note);
  layout->addStretch(1);

  scroll->setWidget(content);
  root->addWidget(scroll);
}

}  // namespace finalis::wallet
