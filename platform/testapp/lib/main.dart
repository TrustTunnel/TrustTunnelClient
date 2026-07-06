import 'package:code_text_field/code_text_field.dart';
import 'package:flutter/material.dart';
import 'package:permission_handler/permission_handler.dart';
import 'package:provider/provider.dart';
import 'package:testapp/flutter_callbacks_impl.dart';
import 'package:testapp/native_communication.dart';
import 'package:flutter_highlight/themes/gruvbox-dark.dart';
import 'dart:io' show File, Platform;
import 'package:path/path.dart' as p;

import 'config.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  final notifier = VpnStateNotifier();
  FlutterCallbacks.setUp(FlutterCallbacksImpl(notifier));
  runApp(
      ChangeNotifierProvider.value(
        value: notifier,
        child: const MyApp()
      )
  );
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  // This widget is the root of your application.
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'TrustTunnel testapp',
      theme: ThemeData(
        // This is the theme of your application.
        //
        // TRY THIS: Try running your application with "flutter run". You'll see
        // the application has a purple toolbar. Then, without quitting the app,
        // try changing the seedColor in the colorScheme below to Colors.green
        // and then invoke "hot reload" (save your changes or press the "hot
        // reload" button in a Flutter-supported IDE, or press "r" if you used
        // the command line to start the app).
        //
        // Notice that the counter didn't reset back to zero; the application
        // state is not lost during the reload. To reset the state, use hot
        // restart instead.
        //
        // This works for code too, not just values: Most code changes can be
        // tested with just a hot reload.
        colorScheme: ColorScheme.fromSeed(seedColor: Colors.deepPurple),
      ),
      home: const MyHomePage(title: 'TrustTunnel testapp'),
    );
  }
}

class MyHomePage extends StatefulWidget {
  const MyHomePage({super.key, required this.title});

  // This widget is the home page of your application. It is stateful, meaning
  // that it has a State object (defined below) that contains fields that affect
  // how it looks.

  // This class is the configuration for the state. It holds the values (in this
  // case the title) provided by the parent (in this case the App widget) and
  // used by the build method of the State. Fields in a Widget subclass are
  // always marked "final".

  final String title;

  @override
  State<MyHomePage> createState() => _MyHomePageState();
}

class _MyHomePageState extends State<MyHomePage> {
  bool _buttonSwitch = false;
  final CodeController _config = CodeController();

  final NativeVpnInterface _nativeVpnInterface = NativeVpnInterface();

  void _processButton() {
    setState(() {
      // This call to setState tells the Flutter framework that something has
      // changed in this State, which causes it to rerun the build method below
      // so that the display can reflect the updated values. If we changed
      // _counter without calling setState(), then the build method would not be
      // called again, and so nothing would appear to happen.
      if (_buttonSwitch) {
        _nativeVpnInterface.stop();
        _buttonSwitch = false;
      } else {
        ensureNotificationsPermissions(context).then(
          (value) {
            if (value) {
              _nativeVpnInterface.start(_config.text);
              _buttonSwitch = true;
            }
          },
        );
      }
    });
  }

  void _reconnect() {
    setState(() {
      _nativeVpnInterface.stop();
      _nativeVpnInterface.start(_config.text);
    });
  }

  Future<void> _exportAndShowLogs() async {
    List<String> files;
    try {
      files = await _nativeVpnInterface.exportLogs();
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Failed to export logs: $e')),
        );
      }
      return;
    }

    if (files.isEmpty) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('No log files available')),
        );
      }
      return;
    }

    if (!mounted) return;

    final dirName = p.basename(File(files.first).parent.path);

    showModalBottomSheet(
      context: context,
      builder: (ctx) => _LogFileList(
        dirName: dirName,
        files: files,
        onView: (path) => _viewLogFile(ctx, path),
      ),
    );
  }

  Future<void> _clearLogs() async {
    try {
      await _nativeVpnInterface.clearLogs();
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Logs cleared')),
        );
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Failed to clear logs: $e')),
        );
      }
    }
  }

  void _viewLogFile(BuildContext parentContext, String path) {
    String raw;
    try {
      final file = File(path);
      if (!file.existsSync()) {
        raw = '';
      } else {
        raw = file.readAsStringSync();
        // Avoid displaying extremely large files
        if (raw.length > 500_000) {
          raw = raw.substring(0, 500_000);
        }
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Error reading log file: $e')),
        );
      }
      return;
    }

    final entries = _parseLogEntries(raw);

    if (entries.isEmpty) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('No log entries found')),
        );
      }
      return;
    }

    Navigator.of(parentContext).pop(); // close bottom sheet

    showDialog(
      context: context,
      builder: (ctx) {
        final scrollController = ScrollController();
        // Scroll to the bottom after the first frame — newest logs are at the end
        WidgetsBinding.instance.addPostFrameCallback((_) {
          if (scrollController.hasClients) {
            scrollController.jumpTo(scrollController.position.maxScrollExtent);
          }
        });

        return AlertDialog(
        title: Text(p.basename(path)),
        content: SizedBox(
          width: double.maxFinite,
          height: MediaQuery.of(context).size.height * 0.7,
          child: ListView.separated(
            controller: scrollController,
            itemCount: entries.length,
            separatorBuilder: (_, __) => Divider(
              height: 1,
              thickness: 1,
              color: Colors.grey.shade300,
            ),
            itemBuilder: (_, i) => Padding(
              padding: const EdgeInsets.symmetric(vertical: 4),
              child: SelectableText(
                entries[i],
                style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
              ),
            ),
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(ctx).pop(),
            child: const Text('Close'),
          ),
        ],
      );
      },
    );
  }

  /// Parse log entries from raw file content.
  ///
  /// Tries the new \x1E record separator first. Falls back to \n-based
  /// splitting for backward compatibility with old log files.
  static List<String> _parseLogEntries(String raw) {
    // Try \x1E first (new format)
    final byRs = raw.split('\x1E');
    if (byRs.length > 1) {
      return byRs
          .map((e) => e.trimRight())
          .where((e) => e.isNotEmpty)
          .toList();
    }
    // Fallback: old format — split by \n
    return raw
        .split('\n')
        .map((e) => e.trimRight())
        .where((e) => e.isNotEmpty)
        .toList();
  }

  @override
  void initState() {
    super.initState();
    _config.text = VpnConfig.defaultConfig;
  }

  @override
  Widget build(BuildContext context) {
    final vpnStateWatcher = context.watch<VpnStateNotifier>();
    return Scaffold(
      appBar: AppBar(
        // TRY THIS: Try changing the color here to a specific color (to
        // Colors.amber, perhaps?) and trigger a hot reload to see the AppBar
        // change color while the other colors stay the same.
        backgroundColor: Theme.of(context).colorScheme.inversePrimary,
        // Here we take the value from the MyHomePage object that was created by
        // the App.build method, and use it to set our appbar title.
        title: Text(widget.title),
      ),
      body: SafeArea(
        // Center is a layout widget. It takes a single child and positions it
        // in the middle of the parent.
        child: Column(
          // Column is also a layout widget. It takes a list of children and
          // arranges them vertically. By default, it sizes itself to fit its
          // children horizontally, and tries to be as tall as its parent.
          //
          // Column has various properties to control how it sizes itself and
          // how it positions its children. Here we use mainAxisAlignment to
          // center the children vertically; the main axis here is the vertical
          // axis because Columns are vertical (the cross axis would be
          // horizontal).
          //
          // TRY THIS: Invoke "debug painting" (choose the "Toggle Debug Paint"
          // action in the IDE, or press "p" in the console), to see the
          // wireframe for each widget.
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Text(
              "Edit the config here:",
              style: Theme.of(context).textTheme.bodyLarge,
            ),
            Expanded(
              child: CodeTheme (
                data: const CodeThemeData(styles: gruvboxDarkTheme),
                child: CodeField(
                  // wrap: true,
                  expands: true,
                  maxLines: null,
                  controller: _config,
                )
              ),
            ),
            const SizedBox(height: 10.0),
            Center(
              child: ElevatedButton(
                onPressed: _processButton,
                child: Text(_buttonSwitch ? 'Disconnect' : 'Connect'),
              ),
            ),
            Center(
              child: ElevatedButton(
                onPressed: _reconnect,
                child: Text('Reconnect'),
              ),
            ),
            const SizedBox(height: 10.0),
            Center(
              child: ElevatedButton(
                onPressed: _exportAndShowLogs,
                child: const Text('Export Logs'),
              ),
            ),
            const SizedBox(height: 10.0),
            Center(
              child: ElevatedButton(
                onPressed: _clearLogs,
                child: const Text('Clear Logs'),
              ),
            ),
            const SizedBox(height: 10.0),
            Text(
              vpnStateWatcher.state.name,
              style: Theme.of(context).textTheme.headlineMedium,
            ),
            const SizedBox(height: 10.0),
          ],
        ),
      ),
    );
  }

  Future<bool> ensureNotificationsPermissions(BuildContext context) async {
    if (Platform.isIOS || Platform.isMacOS) {
      return true;
    }
    // Check the status of the notification permission.
    final status = await Permission.notification.status;

    if (status.isGranted) {
      return true;
    }

    if (context.mounted) {
      await showDialog(
          context: context,
          builder: (BuildContext context) {
            return AlertDialog(
              title: const Text('Notification permissions required'),
              content: const SingleChildScrollView(
                child: Text('TrustTunnel requires the notifications permission granted'),
              ),
              actions: <Widget>[
                TextButton(onPressed: () { Navigator.of(context).pop(); }, child: Text('Ok'))
              ],
            );
          },
      );
    }

    if (status.isDenied) {
      // If the permission is denied, request it.
      if (await Permission.notification.request().isGranted) {
        return true;
      } else {
        return false;
      }
    } else {
      await openAppSettings();
      return false;
    }
  }
}

class _LogFileList extends StatelessWidget {
  const _LogFileList({required this.dirName, required this.files, required this.onView});

  final String dirName;
  final List<String> files;
  final void Function(String path) onView;

  @override
  Widget build(BuildContext context) {
    return SafeArea(
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          const Padding(
            padding: EdgeInsets.all(16.0),
            child: Text(
              'Exported Log Files',
              style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
            ),
          ),
          Padding(
            padding: const EdgeInsets.only(left: 16, right: 16, bottom: 8),
            child: Text(
              dirName,
              style: TextStyle(fontSize: 12, color: Theme.of(context).colorScheme.onSurface.withValues(alpha: 0.6)),
            ),
          ),
          const Divider(height: 1),
          Flexible(
            child: ListView.separated(
              shrinkWrap: true,
              itemCount: files.length,
              separatorBuilder: (_, __) => const Divider(height: 1),
              itemBuilder: (_, i) {
                final name = p.basename(files[i]);
                return ListTile(
                  leading: const Icon(Icons.description),
                  title: Text(name),
                  trailing: const Icon(Icons.chevron_right),
                  onTap: () => onView(files[i]),
                );
              },
            ),
          ),
          const SizedBox(height: 16),
        ],
      ),
    );
  }
}
