#include "activity_page.hpp"

#include <QAbstractItemView>
#include <QComboBox>
#include <QGroupBox>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QScrollArea>
#include <QTableWidget>
#include <QTextEdit>
#include <QVariant>
#include <QVBoxLayout>

namespace finalis::wallet {
namespace {

void configure_page_layout(QVBoxLayout* layout, int spacing = 12) {
  if (!layout) return;
  layout->setContentsMargins(14, 14, 14, 14);
  layout->setSpacing(spacing);
}

void configure_table(QTableWidget* table, const QStringList& headers) {
  table->setColumnCount(headers.size());
  table->setHorizontalHeaderLabels(headers);
  table->setSelectionBehavior(QAbstractItemView::SelectRows);
  table->setSelectionMode(QAbstractItemView::SingleSelection);
  table->setEditTriggers(QAbstractItemView::NoEditTriggers);
  table->setAlternatingRowColors(true);
  table->setSortingEnabled(true);
  table->verticalHeader()->setVisible(false);
  table->horizontalHeader()->setStretchLastSection(true);
  table->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
  table->horizontalHeader()->setMinimumSectionSize(90);
}

}  // namespace

ActivityPage::ActivityPage(QWidget* parent) : QWidget(parent) {
  auto* root = new QVBoxLayout(this);
  root->setContentsMargins(0, 0, 0, 0);

  auto* scroll = new QScrollArea(this);
  scroll->setWidgetResizable(true);
  scroll->setFrameShape(QFrame::NoFrame);
  auto* content = new QWidget(scroll);
  auto* layout = new QVBoxLayout(content);
  configure_page_layout(layout);

  auto* actions = new QHBoxLayout();
  actions->setSpacing(8);
  filter_combo_ = new QComboBox(this);
  filter_combo_->addItems({"All", "On-Chain", "Local", "Mint", "Confidential", "Pending"});
  detail_button_ = new QPushButton("Show Details", this);
  detail_button_->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Preferred);
  actions->addWidget(new QLabel("Show:", this));
  actions->addWidget(filter_combo_);
  finalized_count_label_ = new QLabel("Finalized: 0", this);
  finalized_count_label_->setProperty("role", QVariant(QStringLiteral("chip")));
  pending_count_label_ = new QLabel("Pending: 0", this);
  pending_count_label_->setProperty("role", QVariant(QStringLiteral("chip")));
  local_count_label_ = new QLabel("Local: 0", this);
  local_count_label_->setProperty("role", QVariant(QStringLiteral("chip")));
  mint_count_label_ = new QLabel("Mint: 0", this);
  mint_count_label_->setProperty("role", QVariant(QStringLiteral("chip")));
  confidential_count_label_ = new QLabel("Confidential: 0", this);
  confidential_count_label_->setProperty("role", QVariant(QStringLiteral("chip")));
  actions->addWidget(finalized_count_label_);
  actions->addWidget(pending_count_label_);
  actions->addWidget(local_count_label_);
  actions->addWidget(mint_count_label_);
  actions->addWidget(confidential_count_label_);
  actions->addStretch(1);
  actions->addWidget(detail_button_);
  layout->addLayout(actions);

  table_ = new QTableWidget(this);
  table_->setMinimumHeight(240);
  configure_table(table_, {"Category", "Status", "Amount", "Reference", "State"});
  layout->addWidget(table_);

  auto* detail_label = new QLabel(
      "Details are shown inline for the selected record. Finalized and local-pending items keep their current backend semantics.",
      this);
  detail_label->setWordWrap(true);
  detail_label->setProperty("role", QVariant(QStringLiteral("muted")));
  layout->addWidget(detail_label);

  auto* detail_box = new QGroupBox("Selected Activity", this);
  auto* detail_layout = new QVBoxLayout(detail_box);
  detail_title_label_ = new QLabel("No record selected", detail_box);
  detail_title_label_->setProperty("role", QVariant(QStringLiteral("metric")));
  detail_view_ = new QTextEdit(detail_box);
  detail_view_->setReadOnly(true);
  detail_view_->setMinimumHeight(140);
  detail_view_->setPlainText("Choose an activity row to inspect the current details.");
  detail_layout->addWidget(detail_title_label_);
  detail_layout->addWidget(detail_view_);
  layout->addWidget(detail_box);

  scroll->setWidget(content);
  root->addWidget(scroll);
}

}  // namespace finalis::wallet
