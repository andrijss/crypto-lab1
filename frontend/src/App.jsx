import { useEffect, useRef, useState } from 'react'
import { AlertCircle, Check, Download, FileIcon, LockKeyhole, Plus, X } from 'lucide-react'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Attachment, AttachmentAction, AttachmentActions, AttachmentContent, AttachmentDescription, AttachmentMedia, AttachmentTitle, AttachmentTrigger } from '@/components/ui/attachment'
import { AspectRatio } from '@/components/ui/aspect-ratio'
import { Progress } from '@/components/ui/progress'
import { Spinner } from '@/components/ui/spinner'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardFooter, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Separator } from '@/components/ui/separator'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { ToggleGroup, ToggleGroupItem } from '@/components/ui/toggle-group'

const encodeOptions = (value) => btoa(JSON.stringify(value))
const encodeKey = (value) => btoa(String.fromCharCode(...value))

function SelectField({ id, label, value, onChange, options, disabled }) {
  return (
    <div className="grid gap-2">
      <Label htmlFor={id}>{label}</Label>
      <Select value={String(value)} onValueChange={onChange} disabled={disabled}>
        <SelectTrigger id={id} className="w-full"><SelectValue /></SelectTrigger>
        <SelectContent>
          {options.map(([value, text]) => <SelectItem key={value} value={String(value)}>{text}</SelectItem>)}
        </SelectContent>
      </Select>
    </div>
  )
}

async function request(path, options, body, headers = {}) {
  const response = await fetch(path, {
    method: 'POST',
    headers: {
      'X-Options': encodeOptions(options),
      ...(body ? { 'Content-Type': 'application/octet-stream' } : {}),
      ...headers,
    },
    body,
  })
  const data = await response.json()
  if (!response.ok) throw new Error(data.error || 'Unable to complete the operation.')
  return data
}

function errorMessage(error) {
  return error.message === 'Failed to fetch' ? 'API unavailable. Start the Python server.' : error.message
}

export default function App() {
  const [operation, setOperation] = useState('encrypt')
  const [demo, setDemo] = useState(false)
  const algorithm = 'DES'
  const [mode, setMode] = useState('CBC')
  const [padding, setPadding] = useState('PKCS7')
  const [buffer, setBuffer] = useState(65536)
  const [workers, setWorkers] = useState(1)
  const [file, setFile] = useState(null)
  const [key, setKey] = useState(null)
  const [keyName, setKeyName] = useState('')
  const [error, setError] = useState('')
  const [progress, setProgress] = useState(null)
  const pollingCleanup = useRef(null)
  useEffect(() => () => pollingCleanup.current?.(), [])
  const [pending, setPending] = useState(null)
  const [result, setResult] = useState(null)
  const [preview, setPreview] = useState(null)
  const fileInput = useRef(null)
  const keyInput = useRef(null)
  const busy = pending !== null
  const decrypt = operation === 'decrypt'
  const parallel = mode === 'ECB' || (mode === 'CBC' && decrypt)

  useEffect(() => {
    if (!file) { setPreview(null); return }
    const url = URL.createObjectURL(file)
    setPreview(url)
    return () => URL.revokeObjectURL(url)
  }, [file])

  function resetResult() { setResult(null); setError(''); setProgress(null) }

  function changeDemo(value) {
    if (!value) return
    setDemo(value === 'pixels')
    resetResult()
  }

  async function generateKey() {
    setPending('key')
    resetResult()
    try {
      const data = await request('/api/key', { algorithm })
      setKey(Uint8Array.from(atob(data.key), (character) => character.charCodeAt(0)))
      setKeyName('DES · 64 bits')
      setResult(null)
    } catch (error) { setError(errorMessage(error)) }
    finally { setPending(null) }
  }

  async function loadKey(file) {
    if (!file) return
    setPending('load-key')
    resetResult()
    try {
      if (file.size !== 8) throw new Error('Invalid key length')
      const bytes = new Uint8Array(await file.arrayBuffer())
      if (algorithm === 'DES' && bytes.some((byte) => byte.toString(2).replaceAll('0', '').length % 2 !== 1)) {
        throw new Error('DES: invalid parity bits')
      }
      setKey(bytes)
      setKeyName(file.name)
      setResult(null)
    } catch (error) { setError(errorMessage(error)) }
    finally { setPending(null) }
  }

  function saveKey() {
    const url = URL.createObjectURL(new Blob([key]))
    const anchor = document.createElement('a')
    anchor.href = url
    anchor.download = `${algorithm.toLowerCase()}.key`
    anchor.click()
    setTimeout(() => URL.revokeObjectURL(url), 1000)
  }

  async function run(event) {
    event.preventDefault()
    if (!file || !key || busy) return
    setPending('transform')
    resetResult()
    setProgress({ stage: 'uploading', value: 0 })
    const progressId = crypto.randomUUID().replaceAll('-', '')
    const controller = new AbortController()
    let stopped = false
    let timer
    async function poll() {
      try {
        const response = await fetch(`/api/progress/${progressId}`, { signal: controller.signal, cache: 'no-store' })
        if (response.ok) {
          const state = await response.json()
          if (!stopped) setProgress(state)
        } else if (response.status === 404) {
          const data = await response.json()
          if (!stopped && data.error === 'File not found') {
            setProgress({ stage: 'processing', value: null })
          }
        }
      } catch { /* The operation request reports connection errors. */ }
      finally { if (!stopped) timer = setTimeout(poll, 400) }
    }
    function stopPolling() { stopped = true; clearTimeout(timer); controller.abort() }
    pollingCleanup.current = stopPolling
    poll()
    try {
      const data = await request('/api/transform', {
        key: encodeKey(key), algorithm, mode,
        padding,
        implementation: 'own', buffer: Number(buffer),
        workers: parallel ? Number(workers) : 1,
        decrypt, demo, extension: `.${file.name.split('.').pop().toLowerCase()}`,
      }, file, { 'X-Progress-ID': progressId })
      stopPolling()
      setProgress({ stage: 'completed', value: 100 })
      setResult({ ...data, demo, decrypt, originalPreview: preview })
    } catch (error) { setError(errorMessage(error)); setProgress(null) }
    finally { stopPolling(); pollingCleanup.current = null; setPending(null) }
  }

  return (
    <main className="mx-auto max-w-4xl space-y-6 px-4 py-8 sm:px-6" aria-label="Image encryption">
      <Tabs value={operation} onValueChange={(value) => { setOperation(value); resetResult() }}>
        <TabsList>
          <TabsTrigger value="encrypt" disabled={busy}>Encrypt</TabsTrigger>
          <TabsTrigger value="decrypt" disabled={busy}>Decrypt</TabsTrigger>
        </TabsList>
        <TabsContent value={operation} className="mt-4">
          <form onSubmit={run} aria-busy={busy}>
            <div className="grid items-start gap-6 md:grid-cols-[minmax(0,1fr)_280px]">
              <Card>
                <CardContent className="space-y-6">
                  <div>
                    <Input ref={fileInput} id="image-file" type="file" className="hidden" aria-label="Choose input file" disabled={busy} onChange={(event) => {
                      const selected = event.target.files?.[0]
                      if (selected) {
                        setFile(selected)
                        resetResult()
                      }
                      event.target.value = ''
                    }} />
                    <Attachment className="w-full" state={pending === 'transform' ? progress?.stage === 'uploading' ? 'uploading' : 'processing' : result ? 'done' : 'idle'}>
                      <AttachmentMedia variant={file?.type.startsWith('image/') && preview ? 'image' : 'icon'}>
                        {file?.type.startsWith('image/') && preview ? <img src={preview} alt="" /> : <FileIcon />}
                      </AttachmentMedia>
                      <AttachmentContent>
                        <AttachmentTitle title={file?.name}>{file?.name || 'Choose file'}</AttachmentTitle>
                        {file && <AttachmentDescription>{file.name.includes('.') ? `${file.name.split('.').pop().toUpperCase()} · ` : ''}{(file.size / 1048576).toFixed(2)} MiB</AttachmentDescription>}
                      </AttachmentContent>
                      <AttachmentTrigger disabled={busy} aria-label={file ? 'Change input file' : 'Choose file'} onClick={() => fileInput.current?.click()} />
                      {file && <AttachmentActions>
                        <AttachmentAction type="button" disabled={busy} aria-label={`Remove ${file.name}`} onClick={() => { setFile(null); resetResult() }}><X /></AttachmentAction>
                      </AttachmentActions>}
                    </Attachment>
                  </div>
                  <ToggleGroup type="single" value={demo ? 'pixels' : 'file'} onValueChange={changeDemo} disabled={busy} aria-label="Operation mode">
                    <ToggleGroupItem value="file" aria-label="File encryption">File</ToggleGroupItem>
                    <ToggleGroupItem value="pixels" aria-label="Pixel demonstration">Pixels</ToggleGroupItem>
                  </ToggleGroup>
                  <Separator />
                  <div className="space-y-3">
                    <Label htmlFor="key-status">Key</Label>
                    <Input id="key-status" readOnly value={keyName} placeholder="No key selected" />
                    <div className="flex flex-wrap gap-2">
                      <Button type="button" variant="outline" disabled={busy} onClick={generateKey}>
                        {pending === 'key' ? <Spinner /> : <Plus />}Generate
                      </Button>
                      <Button type="button" variant="outline" disabled={busy} onClick={() => keyInput.current?.click()}>Load key</Button>
                      <Button type="button" variant="outline" size="icon" aria-label="Save key" title="Save key" disabled={!key || busy} onClick={saveKey}><Download /></Button>
                      <Input ref={keyInput} type="file" className="hidden" aria-label="Load binary key" disabled={busy} onChange={(event) => {
                        loadKey(event.target.files?.[0])
                        event.target.value = ''
                      }} />
                    </div>
                  </div>
                </CardContent>
                <CardFooter className="flex-col items-stretch gap-4">
                  {progress && <div className="space-y-2">
                    <div className="flex justify-between text-sm text-muted-foreground" aria-live="polite">
                      <span>{({ processing: 'Processing', uploading: 'Uploading', preparing: 'Preparing', encrypting: 'Encrypting', decrypting: 'Decrypting', verifying: 'Verifying', finalizing: 'Finalizing', completed: 'Completed', failed: 'Failed' })[progress.stage]}</span>
                      <span className="tabular-nums">{progress.value !== null ? `${progress.value}%` : null}</span>
                    </div>
                    <Progress value={progress.value} aria-label="File operation progress" />
                  </div>}
                  <div className="flex justify-end">
                  <Button type="submit" disabled={!file || !key || busy}>
                    {pending === 'transform' ? <Spinner /> : <LockKeyhole />}
                    {pending === 'transform' ? 'Processing…' : decrypt ? 'Decrypt file' : 'Encrypt file'}
                  </Button>
                  </div>
                </CardFooter>
              </Card>
              <Card>
                <CardContent className="space-y-5">
                  <SelectField id="mode" label="Mode" value={mode} disabled={busy} onChange={(value) => { setMode(value); resetResult() }} options={['ECB', 'CBC'].map((value) => [value, value])} />
                  <SelectField id="padding" label="Padding" value={padding} disabled={busy} onChange={(value) => { setPadding(value); resetResult() }} options={[["PKCS7", "PKCS#7"], ["PKCS5", "PKCS#5"], ["X923", "ANSI X9.23"]]} />
                  <Separator />
                  <SelectField id="buffer" label="Buffer" value={buffer} disabled={busy} onChange={(value) => { setBuffer(Number(value)); resetResult() }} options={[16384, 65536, 1048576, 4194304].map((value) => [value, `${value / 1024} KiB`])} />
                  <SelectField id="workers" label="Processes" value={parallel ? workers : 1} disabled={busy || !parallel} onChange={(value) => { setWorkers(Number(value)); resetResult() }} options={[1, 2, 4, 8].map((value) => [value, String(value)])} />
                </CardContent>
              </Card>
            </div>
          </form>
        </TabsContent>
      </Tabs>

      {error && <Alert variant="destructive"><AlertCircle /><AlertDescription>{error}</AlertDescription></Alert>}

      {result && <Card aria-live="polite">
        <CardHeader className="flex flex-row flex-wrap items-center justify-between gap-3">
          <CardTitle><Badge variant="secondary"><Check />{result.stats.verified ? 'Verified' : 'Encrypted'}</Badge></CardTitle>
          <Button asChild variant="outline"><a href={`/api/download/${result.id}`} download={result.name}><Download />Save result</a></Button>
        </CardHeader>
        <CardContent className="space-y-6">
          {result.demo && !result.decrypt && <div className="grid gap-4 sm:grid-cols-2">
            <figure className="space-y-2"><AspectRatio ratio={4 / 3}><img className="h-full w-full rounded-md border bg-muted object-contain" src={result.originalPreview} alt="Original" /></AspectRatio><figcaption className="text-sm text-muted-foreground">Original</figcaption></figure>
            <figure className="space-y-2"><AspectRatio ratio={4 / 3}><img className="h-full w-full rounded-md border bg-muted object-contain" src={`/api/preview/${result.id}`} alt="Encrypted pixels" /></AspectRatio><figcaption className="text-sm text-muted-foreground">{result.stats.algorithm} / {result.stats.mode}</figcaption></figure>
          </div>}
          <Table>
            <TableHeader><TableRow><TableHead>Total time</TableHead><TableHead>Crypto time</TableHead><TableHead>Throughput</TableHead><TableHead>API peak RSS</TableHead></TableRow></TableHeader>
            <TableBody><TableRow>
              <TableCell>{result.stats.total_seconds.toFixed(3)} s</TableCell>
              <TableCell>{result.stats.crypto_seconds.toFixed(3)} s</TableCell>
              <TableCell>{result.stats.mb_s.toFixed(2)} MiB/s</TableCell>
              <TableCell>{result.stats.peak_mb.toFixed(1)} MiB</TableCell>
            </TableRow></TableBody>
          </Table>
        </CardContent>
      </Card>}
    </main>
  )
}
