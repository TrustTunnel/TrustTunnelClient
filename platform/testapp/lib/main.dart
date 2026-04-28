import 'package:code_text_field/code_text_field.dart';
import 'package:flutter/material.dart';
import 'package:permission_handler/permission_handler.dart';
import 'package:provider/provider.dart';
import 'package:testapp/flutter_callbacks_impl.dart';
import 'package:testapp/native_communication.dart';
import 'package:flutter_highlight/themes/gruvbox-dark.dart';
import 'dart:io' show Platform;

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
