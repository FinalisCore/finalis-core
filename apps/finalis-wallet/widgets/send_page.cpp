// SPDX-License-Identifier: MIT

#include "send_page.hpp"

#include <QFormLayout>
#include <QGridLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QComboBox>
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

}  // namespace

SendPage::SendPage(QWidget* parent) : QWidget(parent) {
  auto* root = new QVBoxLayout(this);
  root->setContentsMargins(0, 0, 0, 0);

  auto* scroll = new QScrollArea(this);
  scroll->setWidgetResizable(true);
  scroll->setFrameShape(QFrame::NoFrame);
  auto* content_widget = new QWidget(scroll);
  auto* layout = new QVBoxLayout(content_widget);
  configure_page_layout(layout);

  auto* intro = new QLabel(
      "Review the transaction inline before sending. The wallet signs locally and only observes finalized state through lightserver. "
      "Confidential TxV2 support is currently limited to transparent -> confidential and exact confidential -> transparent sends.",
      this);
  intro->setWordWrap(true);
  intro->setProperty("role", QVariant(QStringLiteral("muted")));
  layout->addWidget(intro);

  review_status_label_ = new QLabel("Enter a recipient and amount to prepare a send review.", this);
  review_status_label_->setWordWrap(true);
  review_status_label_->setProperty("role", QVariant(QStringLiteral("chip")));
  layout->addWidget(review_status_label_, 0, Qt::AlignLeft);

  review_warning_label_ = new QLabel(this);
  review_warning_label_->setWordWrap(true);
  review_warning_label_->hide();
  layout->addWidget(review_warning_label_);

  auto* content = new QVBoxLayout();
  content->setSpacing(14);

  auto* form_box = new QGroupBox("Send On-Chain", this);
  auto* form = new QFormLayout(form_box);
  configure_form_layout(form);

  address_edit_ = new QLineEdit(form_box);
  mode_combo_ = new QComboBox(form_box);
  amount_edit_ = new QLineEdit(form_box);
  fee_edit_ = new QLineEdit(form_box);
  address_edit_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
  mode_combo_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
  amount_edit_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
  fee_edit_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
  fee_edit_->setReadOnly(true);
  address_edit_->setPlaceholderText("sc...");
  mode_combo_->addItem("Transparent -> Transparent");
  mode_combo_->addItem("Transparent -> Confidential");
  mode_combo_->addItem("Confidential -> Transparent");
  amount_edit_->setPlaceholderText("0.00");
  form->addRow("Recipient address", address_edit_);
  form->addRow("Send mode", mode_combo_);
  form->addRow("Amount (FLS)", amount_edit_);
  form->addRow("Fixed fee (FLS)", fee_edit_);

  auto* actions = new QHBoxLayout();
  actions->setSpacing(8);
  max_button_ = new QPushButton("Send Max", form_box);
  import_confidential_request_button_ = new QPushButton("Import Request", form_box);
  review_button_ = new QPushButton("Review Send", form_box);
  send_button_ = new QPushButton("Send", form_box);
  max_button_->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Preferred);
  import_confidential_request_button_->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Preferred);
  review_button_->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Preferred);
  send_button_->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Preferred);
  actions->addWidget(max_button_);
  actions->addWidget(import_confidential_request_button_);
  actions->addWidget(review_button_);
  actions->addWidget(send_button_);
  actions->addStretch(1);
  form->addRow("", actions);
  content->addWidget(form_box);

  auto* review_box = new QGroupBox("Inline Review", this);
  auto* review_grid = new QGridLayout(review_box);
  review_grid->setHorizontalSpacing(12);
  review_grid->setVerticalSpacing(10);
  review_grid->setColumnStretch(1, 1);
  review_grid->addWidget(new QLabel("Recipient", review_box), 0, 0);
  review_recipient_label_ = new QLabel("-", review_box);
  review_recipient_label_->setWordWrap(true);
  review_recipient_label_->setTextInteractionFlags(Qt::TextSelectableByMouse);
  review_grid->addWidget(review_recipient_label_, 0, 1);
  review_grid->addWidget(new QLabel("Amount", review_box), 1, 0);
  review_amount_label_ = new QLabel("-", review_box);
  review_amount_label_->setWordWrap(true);
  review_grid->addWidget(review_amount_label_, 1, 1);
  review_grid->addWidget(new QLabel("Fee", review_box), 2, 0);
  review_fee_label_ = new QLabel("-", review_box);
  review_fee_label_->setWordWrap(true);
  review_grid->addWidget(review_fee_label_, 2, 1);
  review_grid->addWidget(new QLabel("Total spend", review_box), 3, 0);
  review_total_label_ = new QLabel("-", review_box);
  review_total_label_->setWordWrap(true);
  review_grid->addWidget(review_total_label_, 3, 1);
  review_grid->addWidget(new QLabel("Change", review_box), 4, 0);
  review_change_label_ = new QLabel("-", review_box);
  review_change_label_->setWordWrap(true);
  review_grid->addWidget(review_change_label_, 4, 1);
  review_grid->addWidget(new QLabel("Inputs selected", review_box), 5, 0);
  review_inputs_label_ = new QLabel("-", review_box);
  review_inputs_label_->setWordWrap(true);
  review_grid->addWidget(review_inputs_label_, 5, 1);
  review_note_label_ = new QLabel(
      "Use Review Send to compute the current plan. A final confirmation still appears before broadcast.",
      review_box);
  review_note_label_->setWordWrap(true);
  review_note_label_->setProperty("role", QVariant(QStringLiteral("muted")));
  review_grid->addWidget(review_note_label_, 6, 0, 1, 2);
  content->addWidget(review_box);

  layout->addLayout(content);
  layout->addStretch(1);

  scroll->setWidget(content_widget);
  root->addWidget(scroll);
}

}  // namespace finalis::wallet
