import 'dart:typed_data';

import 'package:flutter/material.dart';

import 'package:file_picker/file_picker.dart';
import 'package:matrix/matrix.dart';

import 'package:fluffychat/config/setting_keys.dart';
import 'package:fluffychat/l10n/l10n.dart';
import 'package:fluffychat/utils/file_selector.dart';
import 'package:fluffychat/utils/import_room_keys.dart';
import 'package:fluffychat/widgets/adaptive_dialogs/show_ok_cancel_alert_dialog.dart';
import 'package:fluffychat/widgets/adaptive_dialogs/show_text_input_dialog.dart';
import 'package:fluffychat/widgets/app_lock.dart';
import 'package:fluffychat/widgets/future_loading_dialog.dart';
import 'package:fluffychat/widgets/matrix.dart';
import 'settings_security_view.dart';

class SettingsSecurity extends StatefulWidget {
  const SettingsSecurity({super.key});

  @override
  SettingsSecurityController createState() => SettingsSecurityController();
}

class SettingsSecurityController extends State<SettingsSecurity> {
  void setAppLockAction() async {
    if (AppLock.of(context).isActive) {
      AppLock.of(context).showLockScreen();
    }
    final newLock = await showTextInputDialog(
      useRootNavigator: false,
      context: context,
      title: L10n.of(context).pleaseChooseAPasscode,
      message: L10n.of(context).pleaseEnter4Digits,
      cancelLabel: L10n.of(context).cancel,
      validator: (text) {
        if (text.isEmpty || (text.length == 4 && int.tryParse(text)! >= 0)) {
          return null;
        }
        return L10n.of(context).pleaseEnter4Digits;
      },
      keyboardType: TextInputType.number,
      obscureText: true,
      maxLines: 1,
      minLines: 1,
      maxLength: 4,
    );
    if (newLock != null) {
      await AppLock.of(context).changePincode(newLock);
    }
  }

  void deleteAccountAction() async {
    if (await showOkCancelAlertDialog(
          useRootNavigator: false,
          context: context,
          title: L10n.of(context).warning,
          message: L10n.of(context).deactivateAccountWarning,
          okLabel: L10n.of(context).ok,
          cancelLabel: L10n.of(context).cancel,
          isDestructive: true,
        ) ==
        OkCancelResult.cancel) {
      return;
    }
    final supposedMxid = Matrix.of(context).client.userID!;
    final mxid = await showTextInputDialog(
      useRootNavigator: false,
      context: context,
      title: L10n.of(context).confirmMatrixId,
      validator: (text) => text == supposedMxid
          ? null
          : L10n.of(context).supposedMxid(supposedMxid),
      isDestructive: true,
      okLabel: L10n.of(context).delete,
      cancelLabel: L10n.of(context).cancel,
    );
    if (mxid == null || mxid.isEmpty || mxid != supposedMxid) {
      return;
    }
    final resp = await showFutureLoadingDialog(
      context: context,
      delay: false,
      future: () =>
          Matrix.of(context).client.uiaRequestBackground<IdServerUnbindResult?>(
            (auth) => Matrix.of(context).client.deactivateAccount(auth: auth),
          ),
    );

    if (!resp.isError) {
      await showFutureLoadingDialog(
        context: context,
        future: () => Matrix.of(context).client.logout(),
      );
    }
  }

  void importRoomKeysAction() async {
    final files = await selectFiles(context);
    if (files.isEmpty) return;

    final passphrase = await showTextInputDialog(
      useRootNavigator: false,
      context: context,
      title: L10n.of(context).importRoomKeys,
      message: L10n.of(context).enterKeyExportPassphrase,
      okLabel: L10n.of(context).importNow,
      cancelLabel: L10n.of(context).cancel,
      obscureText: true,
      maxLines: 1,
      minLines: 1,
    );
    if (passphrase == null || passphrase.isEmpty) return;

    final fileBytes = Uint8List.fromList(await files.first.readAsBytes());

    final result = await showFutureLoadingDialog(
      context: context,
      future: () => importRoomKeys(
        Matrix.of(context).client,
        fileBytes,
        passphrase,
      ),
    );

    if (!mounted) return;

    if (!result.isError) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text(
            L10n.of(context).importRoomKeysSuccess(result.result ?? 0),
          ),
        ),
      );
    }
  }

  void exportRoomKeysAction() async {
    final passphrase = await showTextInputDialog(
      useRootNavigator: false,
      context: context,
      title: L10n.of(context).exportRoomKeys,
      message: L10n.of(context).chooseKeyExportPassphrase,
      okLabel: L10n.of(context).ok,
      cancelLabel: L10n.of(context).cancel,
      obscureText: true,
      maxLines: 1,
      minLines: 1,
    );
    if (passphrase == null || passphrase.isEmpty) return;

    final result = await showFutureLoadingDialog(
      context: context,
      future: () => exportRoomKeys(
        Matrix.of(context).client,
        passphrase,
      ),
    );

    if (!mounted) return;
    if (result.isError) return;

    final bytes = result.result;
    if (bytes == null) return;

    await FilePicker.platform.saveFile(
      dialogTitle: L10n.of(context).exportRoomKeys,
      fileName: 'element-keys.txt',
      bytes: bytes,
    );
  }

  Future<void> dehydrateAction() => Matrix.of(context).dehydrateAction(context);

  void changeShareKeysWith(ShareKeysWith? shareKeysWith) async {
    if (shareKeysWith == null) return;
    AppSettings.shareKeysWith.setItem(shareKeysWith.name);
    Matrix.of(context).client.shareKeysWith = shareKeysWith;
    setState(() {});
  }

  @override
  Widget build(BuildContext context) => SettingsSecurityView(this);
}
