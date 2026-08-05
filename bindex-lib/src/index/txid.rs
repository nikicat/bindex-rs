use std::ops::ControlFlow;

use bitcoin_slices::{bsl, Visit as _};

use crate::index::{BlockBytes, Error, HashPrefixRow, IndexedBlock, Prefix, TxNum};

struct IndexVisitor<'a> {
    result: &'a mut IndexedBlock<HashPrefixRow>,
}

impl bitcoin_slices::Visitor for IndexVisitor<'_> {
    fn visit_transaction(&mut self, tx: &bsl::Transaction) -> ControlFlow<()> {
        // txid_sha2 = the same double-SHA256 computed with hardware SHA
        // instructions; its raw digest order matches sha256d::Hash's
        // internal byte order, so the prefix is byte-identical
        let prefix = Prefix::new(tx.txid_sha2().as_slice());
        self.result
            .rows
            .push(HashPrefixRow::new(prefix, self.result.next_txnum));
        self.result.next_txnum.increment_by(1);
        ControlFlow::Continue(())
    }
}

pub fn index(block: &BlockBytes, txnum: TxNum) -> Result<IndexedBlock<HashPrefixRow>, Error> {
    let mut result = IndexedBlock::new(txnum);
    let mut visitor = IndexVisitor {
        result: &mut result,
    };
    let res = bsl::Block::visit(&block.0, &mut visitor).map_err(Error::Parse)?;
    if !res.remaining().is_empty() {
        return Err(Error::Leftover(res.remaining().len()));
    }
    Ok(result)
}
