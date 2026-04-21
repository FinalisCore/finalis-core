// SPDX-License-Identifier: MIT

#pragma once

#include <QWidget>

class QComboBox;
class QLabel;
class QPushButton;

namespace finalis::wallet {

class SettingsPage final : public QWidget {
 public:
  explicit SettingsPage(QWidget* parent = nullptr);

  QComboBox* theme_combo() const { return theme_combo_; }
  QLabel* branding_symbol_label() const { return branding_symbol_label_; }
  QPushButton* about_button() const { return about_button_; }

 private:
  QComboBox* theme_combo_{nullptr};
  QLabel* branding_symbol_label_{nullptr};
  QPushButton* about_button_{nullptr};
};

}  // namespace finalis::wallet
