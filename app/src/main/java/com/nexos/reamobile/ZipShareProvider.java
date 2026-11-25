package com.nexos.reamobile;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.UriMatcher;
import android.content.res.AssetFileDescriptor;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.ParcelFileDescriptor;
import android.provider.OpenableColumns;
import java.io.File;
import java.io.FileNotFoundException;

/**
 * Sirve el ZIP de extracción (cache/rea_extraccion.zip) y el informe
 * (cache/informe_rea.txt) a otras apps para compartir. Solo framework,
 * sin AndroidX. Solo lectura; URIs de nombre exacto, sin comodines.
 */
public class ZipShareProvider extends ContentProvider {

    public static final String AUTHORITY = "com.nexos.reamobile.zipshare";
    public static final String FILE_NAME = "rea_extraccion.zip";
    public static final String REPORT_NAME = "informe_rea.txt";
    private static final int CODE_ZIP = 1;
    private static final int CODE_REPORT = 2;

    private static final UriMatcher MATCHER = new UriMatcher(UriMatcher.NO_MATCH);

    static {
        MATCHER.addURI(AUTHORITY, FILE_NAME, CODE_ZIP);
        MATCHER.addURI(AUTHORITY, REPORT_NAME, CODE_REPORT);
    }

    public static Uri zipUri() {
        return new Uri.Builder().scheme("content").authority(AUTHORITY).path(FILE_NAME).build();
    }

    public static Uri reportUri() {
        return new Uri.Builder().scheme("content").authority(AUTHORITY).path(REPORT_NAME).build();
    }

    @Override
    public boolean onCreate() {
        return true;
    }

    private File fileFor(int code) throws FileNotFoundException {
        if (getContext() == null) throw new FileNotFoundException("sin contexto");
        String name;
        if (code == CODE_ZIP) name = FILE_NAME;
        else if (code == CODE_REPORT) name = REPORT_NAME;
        else throw new FileNotFoundException("uri no válido");
        File f = new File(getContext().getCacheDir(), name);
        if (!f.isFile()) throw new FileNotFoundException("sin fichero: " + name);
        return f;
    }

    private File zipFile() throws FileNotFoundException {
        return fileFor(CODE_ZIP);
    }

    @Override
    public ParcelFileDescriptor openFile(Uri uri, String mode) throws FileNotFoundException {
        int code = MATCHER.match(uri);
        if (code == UriMatcher.NO_MATCH) throw new FileNotFoundException("uri no válido");
        return ParcelFileDescriptor.open(fileFor(code), ParcelFileDescriptor.MODE_READ_ONLY);
    }

    @Override
    public AssetFileDescriptor openAssetFile(Uri uri, String mode) throws FileNotFoundException {
        int code = MATCHER.match(uri);
        if (code == UriMatcher.NO_MATCH) throw new FileNotFoundException("uri no válido");
        File f = fileFor(code);
        ParcelFileDescriptor pfd =
                ParcelFileDescriptor.open(f, ParcelFileDescriptor.MODE_READ_ONLY);
        return new AssetFileDescriptor(pfd, 0, f.length());
    }

    @Override
    public String getType(Uri uri) {
        return MATCHER.match(uri) == CODE_REPORT ? "text/plain" : "application/zip";
    }

    @Override
    public Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs,
                        String sortOrder) {
        try {
            int code = MATCHER.match(uri);
            if (code == UriMatcher.NO_MATCH) return null;
            File f = fileFor(code);
            MatrixCursor c = new MatrixCursor(
                    new String[]{OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE});
            c.addRow(new Object[]{f.getName(), f.length()});
            return c;
        } catch (Exception e) {
            return null;
        }
    }

    @Override
    public Uri insert(Uri uri, ContentValues values) {
        throw new UnsupportedOperationException("solo lectura");
    }

    @Override
    public int delete(Uri uri, String selection, String[] selectionArgs) {
        throw new UnsupportedOperationException("solo lectura");
    }

    @Override
    public int update(Uri uri, ContentValues values, String selection, String[] selectionArgs) {
        throw new UnsupportedOperationException("solo lectura");
    }
}
